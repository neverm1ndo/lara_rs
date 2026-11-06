use crate::shared::file_storage::path::RelativeStoragePath;

use super::{ConfigurationFileKind, ConfigurationFilePolicy};

/// Defense in depth for opaque artifact replacement. An exact allowlist entry
/// is necessary, but executable, native and private targets remain forbidden.
pub struct ConfigurationArtifactPolicy;

impl ConfigurationArtifactPolicy {
    pub fn permits(
        path: &RelativeStoragePath,
        allowlist: &[RelativeStoragePath],
        file_policy: &ConfigurationFilePolicy,
    ) -> bool {
        if path.is_root()
            || !allowlist.iter().any(|allowed| allowed == path)
            || file_policy.is_ignored(path)
            || file_policy.classify(path) != ConfigurationFileKind::Binary
        {
            return false;
        }

        if path.components().any(|component| {
            let normalized = component.to_ascii_lowercase();
            normalized.starts_with('.')
                || matches!(
                    normalized.as_str(),
                    "omp-server" | "samp03svr" | "systemd" | "secrets" | "private"
                )
        }) {
            return false;
        }

        let extension = path
            .file_name()
            .and_then(|name| name.rsplit_once('.'))
            .map(|(_, extension)| extension.to_ascii_lowercase());
        let file_name = path.file_name().unwrap().to_ascii_lowercase();
        if file_name.contains(".so.")
            || file_name.contains(".env.")
            || file_name.contains(".service.")
            || file_name.ends_with(".dylib")
            || file_name.ends_with(".bundle")
        {
            return false;
        }
        !extension.as_deref().is_some_and(|extension| {
            matches!(
                extension,
                "env" | "so" | "dll" | "exe" | "service" | "socket" | "key" | "pem" | "p12" | "pfx"
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        configuration::domain::BinaryExtension, shared::file_storage::path::StorageFileName,
    };

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    #[test]
    fn requires_exact_binary_path_and_rejects_protected_targets() {
        let policy = ConfigurationFilePolicy::new(
            [
                BinaryExtension::new("amx").unwrap(),
                BinaryExtension::new("so").unwrap(),
            ],
            [
                StorageFileName::new("omp-server").unwrap(),
                StorageFileName::new("native.so.1").unwrap(),
            ],
            [path("logs")],
        )
        .unwrap();
        let allowlist = [
            path("gamemodes/test.amx"),
            path("plugins/native.so"),
            path("plugins/native.so.1"),
            path("omp-server"),
            path("logs/test.amx"),
        ];
        assert!(ConfigurationArtifactPolicy::permits(
            &path("gamemodes/test.amx"),
            &allowlist,
            &policy
        ));
        for denied in [
            "gamemodes/other.amx",
            "gamemodes/TEST.amx",
            "gamemodes/test.cfg",
            "plugins/native.so",
            "plugins/native.so.1",
            "omp-server",
            "logs/test.amx",
        ] {
            assert!(!ConfigurationArtifactPolicy::permits(
                &path(denied),
                &allowlist,
                &policy
            ));
        }
    }
}
