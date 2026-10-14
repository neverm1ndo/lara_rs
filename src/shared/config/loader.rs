use std::{env, path::Path};

use ::config::{ConfigBuilder, Environment, File, Map, builder::DefaultState};

use super::{AppConfig, ConfigError};

const DEFAULT_CONFIG_FILE: &str = "config/default.toml";
const CONFIG_FILE_ENV: &str = "LARA_CONFIG_FILE";
const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:3000";
const DEFAULT_JWT_TTL_SECONDS: i64 = 3_600;
const MIN_JWT_TTL_SECONDS: i64 = 60;
const MAX_JWT_TTL_SECONDS: i64 = 86_400;
const MIN_JWT_SECRET_BYTES: usize = 32;

impl AppConfig {
    /// Loads configuration in ascending priority order:
    /// built-in defaults, optional default TOML, an explicitly selected TOML,
    /// deprecated environment names, and finally `LARA_*` variables.
    pub fn load() -> Result<Self, ConfigError> {
        let mut builder = ::config::Config::builder()
            .set_default("server.bind_address", DEFAULT_BIND_ADDRESS)?
            .set_default("jwt.ttl_seconds", DEFAULT_JWT_TTL_SECONDS)?
            .add_source(File::from(Path::new(DEFAULT_CONFIG_FILE)).required(false));

        if let Some(path) = nonempty_env(CONFIG_FILE_ENV) {
            tracing::info!(config_file = %path, "loading configuration overlay");
            builder = builder.add_source(File::from(Path::new(&path)).required(true));
        }

        builder = apply_legacy_environment(builder)?;
        builder = builder.add_source(lara_environment(None));

        let config = builder.build()?.try_deserialize::<Self>()?;
        config.validate()?;
        log_loaded_configuration(&config);
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        require_nonempty("jwt.secret", self.jwt.secret.expose_secret())?;
        require_nonempty("jwt.issuer", &self.jwt.issuer)?;
        require_nonempty("jwt.audience", &self.jwt.audience)?;
        require_nonempty("mysql.url", self.mysql.url.expose_secret())?;
        require_nonempty("mongodb.uri", self.mongodb.uri.expose_secret())?;
        require_nonempty("mongodb.database", &self.mongodb.database)?;

        if self.jwt.secret.expose_secret().len() < MIN_JWT_SECRET_BYTES {
            return Err(ConfigError::JwtSecretTooShort {
                minimum: MIN_JWT_SECRET_BYTES,
            });
        }

        parse_jwt_ttl_seconds(&self.jwt.ttl_seconds.to_string())?;
        Ok(())
    }
}

fn log_loaded_configuration(config: &AppConfig) {
    tracing::info!(
        bind_address = %config.server.bind_address,
        jwt_issuer = %config.jwt.issuer,
        jwt_audience = %config.jwt.audience,
        jwt_ttl_seconds = config.jwt.ttl_seconds,
        mongodb_database = %config.mongodb.database,
        "server configuration loaded"
    );
}

fn lara_environment(source: Option<Map<String, String>>) -> Environment {
    Environment::with_prefix("LARA")
        .prefix_separator("_")
        .separator("__")
        .try_parsing(true)
        .ignore_empty(true)
        .source(source)
}

fn apply_legacy_environment(
    builder: ConfigBuilder<DefaultState>,
) -> Result<ConfigBuilder<DefaultState>, ConfigError> {
    apply_legacy_environment_from(builder, &nonempty_env)
}

fn apply_legacy_environment_from<F>(
    mut builder: ConfigBuilder<DefaultState>,
    read: &F,
) -> Result<ConfigBuilder<DefaultState>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    builder = legacy_string_override(
        builder,
        "server.bind_address",
        "BIND_ADDRESS",
        "LARA_SERVER__BIND_ADDRESS",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "mysql.url",
        "MYSQL_DATABASE_URL",
        "LARA_MYSQL__URL",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "mongodb.uri",
        "MONGODB_URI",
        "LARA_MONGODB__URI",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "mongodb.database",
        "MONGODB_DATABASE",
        "LARA_MONGODB__DATABASE",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "jwt.secret",
        "LSRV_SECRET",
        "LARA_JWT__SECRET",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "jwt.issuer",
        "JWT_ISSUER",
        "LARA_JWT__ISSUER",
        read,
    )?;
    builder = legacy_string_override(
        builder,
        "jwt.audience",
        "JWT_AUDIENCE",
        "LARA_JWT__AUDIENCE",
        read,
    )?;

    if read("LARA_JWT__TTL_SECONDS").is_none()
        && let Some(value) = read("JWT_TTL_SECONDS")
    {
        warn_legacy_environment("JWT_TTL_SECONDS", "LARA_JWT__TTL_SECONDS");
        builder = builder.set_override("jwt.ttl_seconds", parse_jwt_ttl_seconds(&value)?)?;
    }

    Ok(builder)
}

fn legacy_string_override(
    builder: ConfigBuilder<DefaultState>,
    key: &'static str,
    legacy_name: &'static str,
    replacement_name: &'static str,
    read: &impl Fn(&str) -> Option<String>,
) -> Result<ConfigBuilder<DefaultState>, ConfigError> {
    if read(replacement_name).is_some() {
        return Ok(builder);
    }

    match read(legacy_name) {
        Some(value) => {
            warn_legacy_environment(legacy_name, replacement_name);
            Ok(builder.set_override(key, value)?)
        }
        None => Ok(builder),
    }
}

fn warn_legacy_environment(legacy_name: &'static str, replacement_name: &'static str) {
    tracing::warn!(
        legacy_variable = legacy_name,
        replacement_variable = replacement_name,
        "deprecated configuration environment variable is in use"
    );
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn require_nonempty(key: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::EmptyValue { key });
    }

    Ok(())
}

fn parse_jwt_ttl_seconds(value: &str) -> Result<i64, ConfigError> {
    let seconds = value
        .parse::<i64>()
        .map_err(|_| ConfigError::InvalidJwtTtl)?;

    (MIN_JWT_TTL_SECONDS..=MAX_JWT_TTL_SECONDS)
        .contains(&seconds)
        .then_some(seconds)
        .ok_or(ConfigError::InvalidJwtTtl)
}

#[cfg(test)]
mod tests {
    use ::config::FileFormat;

    use super::*;

    type ConfigMutation = Box<dyn Fn(&mut AppConfig)>;

    fn valid_config() -> AppConfig {
        AppConfig {
            server: super::super::model::ServerConfig {
                bind_address: "127.0.0.1:3000".parse().unwrap(),
            },
            jwt: super::super::model::JwtConfig {
                secret: super::super::model::SecretString::new("a".repeat(MIN_JWT_SECRET_BYTES)),
                issuer: "lara".into(),
                audience: "lara-api".into(),
                ttl_seconds: DEFAULT_JWT_TTL_SECONDS,
            },
            mysql: super::super::model::MySqlConfig {
                url: super::super::model::SecretString::new("mysql://localhost/lara"),
            },
            mongodb: super::super::model::MongoConfig {
                uri: super::super::model::SecretString::new("mongodb://localhost:27017"),
                database: "lara".into(),
            },
        }
    }

    #[test]
    fn validates_jwt_ttl_range() {
        assert_eq!(parse_jwt_ttl_seconds("60").unwrap(), 60);
        assert_eq!(parse_jwt_ttl_seconds("3600").unwrap(), 3_600);
        assert_eq!(parse_jwt_ttl_seconds("86400").unwrap(), 86_400);

        for invalid in ["", "not-a-number", "0", "59", "86401", "-1"] {
            assert!(matches!(
                parse_jwt_ttl_seconds(invalid),
                Err(ConfigError::InvalidJwtTtl)
            ));
        }
    }

    #[test]
    fn accepts_semantically_valid_configuration() {
        valid_config().validate().unwrap();
    }

    #[test]
    fn rejects_empty_required_values() {
        let mut cases: Vec<(&str, ConfigMutation)> = vec![
            (
                "jwt.secret",
                Box::new(|config| config.jwt.secret = super::super::model::SecretString::new(" ")),
            ),
            (
                "jwt.issuer",
                Box::new(|config| config.jwt.issuer = " ".into()),
            ),
            (
                "jwt.audience",
                Box::new(|config| config.jwt.audience = "".into()),
            ),
            (
                "mysql.url",
                Box::new(|config| config.mysql.url = super::super::model::SecretString::new("")),
            ),
            (
                "mongodb.uri",
                Box::new(|config| config.mongodb.uri = super::super::model::SecretString::new(" ")),
            ),
            (
                "mongodb.database",
                Box::new(|config| config.mongodb.database = "".into()),
            ),
        ];

        for (key, mutate) in cases.drain(..) {
            let mut config = valid_config();
            mutate(&mut config);

            assert!(matches!(
                config.validate(),
                Err(ConfigError::EmptyValue { key: invalid_key }) if invalid_key == key
            ));
        }
    }

    #[test]
    fn rejects_short_jwt_secret() {
        let mut config = valid_config();
        config.jwt.secret = super::super::model::SecretString::new("a".repeat(31));

        assert!(matches!(
            config.validate(),
            Err(ConfigError::JwtSecretTooShort { minimum: 32 })
        ));
    }

    #[test]
    fn rejects_out_of_range_ttl_during_full_validation() {
        let mut config = valid_config();
        config.jwt.ttl_seconds = 59;

        assert!(matches!(config.validate(), Err(ConfigError::InvalidJwtTtl)));
    }

    #[test]
    fn loads_all_legacy_environment_names_during_migration() {
        let defaults = include_str!("../../../config/default.toml");
        let legacy: Map<String, String> = Map::from([
            ("BIND_ADDRESS".into(), "0.0.0.0:8080".into()),
            ("MYSQL_DATABASE_URL".into(), "mysql://legacy/lara".into()),
            ("MONGODB_URI".into(), "mongodb://legacy:27017".into()),
            ("MONGODB_DATABASE".into(), "legacy-database".into()),
            (
                "LSRV_SECRET".into(),
                "legacy-secret-containing-32-bytes!".into(),
            ),
            ("JWT_ISSUER".into(), "legacy-issuer".into()),
            ("JWT_AUDIENCE".into(), "legacy-audience".into()),
            ("JWT_TTL_SECONDS".into(), "7200".into()),
        ]);
        let builder =
            ::config::Config::builder().add_source(File::from_str(defaults, FileFormat::Toml));
        let builder =
            apply_legacy_environment_from(builder, &|name| legacy.get(name).cloned()).unwrap();

        let config = builder
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();
        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.mysql.url.expose_secret(), "mysql://legacy/lara");
        assert_eq!(config.mongodb.uri.expose_secret(), "mongodb://legacy:27017");
        assert_eq!(config.mongodb.database, "legacy-database");
        assert_eq!(config.jwt.issuer, "legacy-issuer");
        assert_eq!(config.jwt.audience, "legacy-audience");
        assert_eq!(config.jwt.ttl_seconds, 7_200);
    }

    #[test]
    fn modern_environment_names_take_priority_over_legacy_names() {
        let defaults = include_str!("../../../config/default.toml");
        let variables: Map<String, String> = Map::from([
            (
                "LSRV_SECRET".into(),
                "legacy-secret-containing-32-bytes!".into(),
            ),
            (
                "LARA_JWT__SECRET".into(),
                "modern-secret-containing-32-bytes!".into(),
            ),
            ("JWT_TTL_SECONDS".into(), "7200".into()),
            ("LARA_JWT__TTL_SECONDS".into(), "1800".into()),
            ("MYSQL_DATABASE_URL".into(), "mysql://legacy/lara".into()),
            ("LARA_MYSQL__URL".into(), "mysql://modern/lara".into()),
            ("MONGODB_URI".into(), "mongodb://legacy:27017".into()),
            ("LARA_MONGODB__URI".into(), "mongodb://modern:27017".into()),
        ]);
        let modern = Map::from([
            (
                "LARA_JWT__SECRET".into(),
                "modern-secret-containing-32-bytes!".into(),
            ),
            ("LARA_JWT__TTL_SECONDS".into(), "1800".into()),
            ("LARA_MYSQL__URL".into(), "mysql://modern/lara".into()),
            ("LARA_MONGODB__URI".into(), "mongodb://modern:27017".into()),
        ]);
        let builder =
            ::config::Config::builder().add_source(File::from_str(defaults, FileFormat::Toml));
        let builder = apply_legacy_environment_from(builder, &|name| variables.get(name).cloned())
            .unwrap()
            .add_source(lara_environment(Some(modern)));

        let config = builder
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();
        assert_eq!(
            config.jwt.secret.expose_secret(),
            "modern-secret-containing-32-bytes!"
        );
        assert_eq!(config.jwt.ttl_seconds, 1_800);
        assert_eq!(config.mysql.url.expose_secret(), "mysql://modern/lara");
        assert_eq!(config.mongodb.uri.expose_secret(), "mongodb://modern:27017");
    }

    #[test]
    fn committed_defaults_require_external_secrets() {
        let defaults = include_str!("../../../config/default.toml");

        let result = ::config::Config::builder()
            .add_source(File::from_str(defaults, FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>();

        assert!(result.is_err());
    }

    #[test]
    fn environment_overrides_file_values_using_nested_keys() {
        let base = r#"
            [server]
            bind_address = "127.0.0.1:3000"

            [jwt]
            secret = "file-secret"
            issuer = "lara"
            audience = "lara-api"
            ttl_seconds = 3600

            [mysql]
            url = "mysql://localhost/file"

            [mongodb]
            uri = "mongodb://localhost:27017"
            database = "lara"
        "#;
        let environment = Map::from([
            ("LARA_SERVER__BIND_ADDRESS".into(), "0.0.0.0:8080".into()),
            (
                "LARA_JWT__SECRET".into(),
                "environment-secret-with-32-bytes!".into(),
            ),
            ("LARA_JWT__TTL_SECONDS".into(), "7200".into()),
        ]);

        let config = ::config::Config::builder()
            .add_source(File::from_str(base, FileFormat::Toml))
            .add_source(lara_environment(Some(environment)))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();

        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(
            config.jwt.secret.expose_secret(),
            "environment-secret-with-32-bytes!"
        );
        assert_eq!(config.jwt.ttl_seconds, 7_200);
        assert_eq!(config.mysql.url.expose_secret(), "mysql://localhost/file");
    }

    #[test]
    fn explicit_file_overrides_defaults_before_environment_is_applied() {
        let defaults = include_str!("../../../config/default.toml");
        let overlay = r#"
            [server]
            bind_address = "0.0.0.0:8080"

            [jwt]
            issuer = "overlay-issuer"
            ttl_seconds = 1800

            [mongodb]
            database = "overlay-database"
        "#;
        let environment = Map::from([
            (
                "LARA_JWT__SECRET".into(),
                "environment-secret-with-32-bytes!".into(),
            ),
            ("LARA_JWT__ISSUER".into(), "environment-issuer".into()),
            ("LARA_MYSQL__URL".into(), "mysql://localhost/lara".into()),
            (
                "LARA_MONGODB__URI".into(),
                "mongodb://localhost:27017".into(),
            ),
        ]);

        let config = ::config::Config::builder()
            .add_source(File::from_str(defaults, FileFormat::Toml))
            .add_source(File::from_str(overlay, FileFormat::Toml))
            .add_source(lara_environment(Some(environment)))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();
        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.jwt.issuer, "environment-issuer");
        assert_eq!(config.jwt.audience, "lara-api");
        assert_eq!(config.jwt.ttl_seconds, 1_800);
        assert_eq!(config.mongodb.database, "overlay-database");
    }

    #[test]
    fn committed_default_file_combines_with_environment_secrets() {
        let defaults = include_str!("../../../config/default.toml");
        let secrets = Map::from([
            (
                "LARA_JWT__SECRET".into(),
                "environment-secret-with-32-bytes!".into(),
            ),
            ("LARA_MYSQL__URL".into(), "mysql://localhost/lara".into()),
            (
                "LARA_MONGODB__URI".into(),
                "mongodb://localhost:27017".into(),
            ),
        ]);

        let config = ::config::Config::builder()
            .add_source(File::from_str(defaults, FileFormat::Toml))
            .add_source(lara_environment(Some(secrets)))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap();

        config.validate().unwrap();

        assert_eq!(config.server.bind_address.to_string(), "127.0.0.1:3000");
        assert_eq!(config.jwt.issuer, "lara");
        assert_eq!(config.jwt.audience, "lara-api");
        assert_eq!(config.jwt.ttl_seconds, 3_600);
        assert_eq!(config.mongodb.database, "lara");
        assert_eq!(
            config.jwt.secret.expose_secret(),
            "environment-secret-with-32-bytes!"
        );
    }
}
