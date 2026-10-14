use std::{fmt, net::SocketAddr};

use serde::Deserialize;

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    #[cfg(test)]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub mysql: MySqlConfig,
    pub mongodb: MongoConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind_address: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: SecretString,
    pub issuer: String,
    pub audience: String,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MySqlConfig {
    pub url: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MongoConfig {
    pub uri: SecretString,
    pub database: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_secrets_recursively() {
        let config = AppConfig {
            server: ServerConfig {
                bind_address: "127.0.0.1:3000".parse().unwrap(),
            },
            jwt: JwtConfig {
                secret: SecretString::new("jwt-secret"),
                issuer: "lara".into(),
                audience: "lara-api".into(),
                ttl_seconds: 3_600,
            },
            mysql: MySqlConfig {
                url: SecretString::new("mysql://user:password@localhost/lara"),
            },
            mongodb: MongoConfig {
                uri: SecretString::new("mongodb://user:password@localhost/lara"),
                database: "lara".into(),
            },
        };

        let debug = format!("{config:?}");

        assert!(!debug.contains("jwt-secret"));
        assert!(!debug.contains("user:password"));
        assert_eq!(debug.matches("[REDACTED]").count(), 3);
    }

    #[test]
    fn deserializes_nested_configuration_model() {
        let config: AppConfig = serde_json::from_value(serde_json::json!({
            "server": { "bind_address": "0.0.0.0:8080" },
            "jwt": {
                "secret": "jwt-secret",
                "issuer": "lara",
                "audience": "lara-api",
                "ttl_seconds": 3600
            },
            "mysql": { "url": "mysql://localhost/lara" },
            "mongodb": {
                "uri": "mongodb://localhost:27017",
                "database": "lara"
            }
        }))
        .unwrap();

        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.jwt.secret.expose_secret(), "jwt-secret");
        assert_eq!(config.jwt.ttl_seconds, 3_600);
        assert_eq!(config.mysql.url.expose_secret(), "mysql://localhost/lara");
        assert_eq!(config.mongodb.database, "lara");
    }
}
