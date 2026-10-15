use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use thiserror::Error;

use super::path::RelativeStoragePath;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStorageLimits {
    pub max_tree_depth: usize,
    pub max_tree_entries: usize,
    pub max_stream_size_bytes: u64,
}

impl FileStorageLimits {
    pub fn new(
        max_tree_depth: usize,
        max_tree_entries: usize,
        max_stream_size_bytes: u64,
    ) -> Result<Self, LocalFileStorageError> {
        if max_tree_depth == 0 || max_tree_entries == 0 || max_stream_size_bytes == 0 {
            return Err(LocalFileStorageError::InvalidLimits);
        }

        Ok(Self {
            max_tree_depth,
            max_tree_entries,
            max_stream_size_bytes,
        })
    }
}

/// A filesystem capability permanently confined to one canonical directory.
///
/// Absolute paths are intentionally not accepted by any operation after
/// construction. A narrower capability can only be created with [`Self::scoped`].
#[derive(Debug, Clone)]
pub struct LocalFileStorage {
    root: Arc<PathBuf>,
    limits: FileStorageLimits,
}

impl LocalFileStorage {
    pub async fn open(
        root: impl AsRef<Path>,
        limits: FileStorageLimits,
    ) -> Result<Self, LocalFileStorageError> {
        let requested = absolute_path(root.as_ref())?;
        let metadata = tokio::fs::symlink_metadata(&requested).await?;

        if is_link_or_reparse_point(&metadata) {
            return Err(LocalFileStorageError::LinkOrReparsePoint);
        }
        if !metadata.is_dir() {
            return Err(LocalFileStorageError::NotDirectory);
        }

        let canonical = tokio::fs::canonicalize(requested).await?;
        Ok(Self {
            root: Arc::new(canonical),
            limits,
        })
    }

    pub fn limits(&self) -> FileStorageLimits {
        self.limits
    }

    pub async fn scoped(&self, scope: &RelativeStoragePath) -> Result<Self, LocalFileStorageError> {
        if scope.is_root() {
            return Ok(self.clone());
        }

        let mut candidate = self.root.as_ref().clone();
        for component in scope.components() {
            candidate.push(component);
            let metadata = tokio::fs::symlink_metadata(&candidate).await?;
            if is_link_or_reparse_point(&metadata) {
                return Err(LocalFileStorageError::LinkOrReparsePoint);
            }
        }

        let metadata = tokio::fs::metadata(&candidate).await?;
        if !metadata.is_dir() {
            return Err(LocalFileStorageError::NotDirectory);
        }

        let canonical = tokio::fs::canonicalize(candidate).await?;
        if !canonical.starts_with(self.root.as_ref()) {
            return Err(LocalFileStorageError::OutsideRoot);
        }

        Ok(Self {
            root: Arc::new(canonical),
            limits: self.limits,
        })
    }

    #[cfg(test)]
    fn root_path(&self) -> &Path {
        self.root.as_path()
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, io::Error> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn is_link_or_reparse_point(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    false
}

#[derive(Debug, Error)]
pub enum LocalFileStorageError {
    #[error("file-storage limits must be positive")]
    InvalidLimits,
    #[error("file-storage root or scope is not a directory")]
    NotDirectory,
    #[error("file-storage root or scope must not be a symbolic link or reparse point")]
    LinkOrReparsePoint,
    #[error("file-storage scope resolves outside its capability root")]
    OutsideRoot,
    #[error("file-storage I/O error")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use uuid::Uuid;

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lara-file-storage-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let temp = std::env::temp_dir().canonicalize().unwrap();
            let target = self.0.canonicalize().unwrap_or_else(|_| self.0.clone());
            if target.starts_with(temp) {
                let _ = fs::remove_dir_all(target);
            }
        }
    }

    fn limits() -> FileStorageLimits {
        FileStorageLimits::new(32, 10_000, 10 * 1024 * 1024).unwrap()
    }

    #[test]
    fn limits_must_be_positive() {
        assert!(matches!(
            FileStorageLimits::new(0, 1, 1),
            Err(LocalFileStorageError::InvalidLimits)
        ));
        assert!(matches!(
            FileStorageLimits::new(1, 0, 1),
            Err(LocalFileStorageError::InvalidLimits)
        ));
        assert!(matches!(
            FileStorageLimits::new(1, 1, 0),
            Err(LocalFileStorageError::InvalidLimits)
        ));
    }

    #[tokio::test]
    async fn opens_only_existing_directories_and_canonicalizes_the_root() {
        let directory = TestDirectory::new();
        let storage = LocalFileStorage::open(&directory.0, limits())
            .await
            .unwrap();

        assert!(storage.root_path().is_absolute());
        assert_eq!(storage.root_path(), directory.0.canonicalize().unwrap());
        assert_eq!(storage.limits(), limits());

        let file = directory.0.join("server.cfg");
        fs::write(&file, "hostname open.mp").unwrap();
        assert!(matches!(
            LocalFileStorage::open(file, limits()).await,
            Err(LocalFileStorageError::NotDirectory)
        ));
    }

    #[tokio::test]
    async fn creates_a_capability_for_an_existing_child_directory() {
        let directory = TestDirectory::new();
        let config = directory.0.join("scriptfiles").join("config");
        fs::create_dir_all(&config).unwrap();

        let storage = LocalFileStorage::open(&directory.0, limits())
            .await
            .unwrap();
        let scope = RelativeStoragePath::new("scriptfiles/config").unwrap();
        let scoped = storage.scoped(&scope).await.unwrap();

        assert_eq!(scoped.root_path(), config.canonicalize().unwrap());
        assert_eq!(scoped.limits(), storage.limits());
        assert_eq!(
            storage
                .scoped(&RelativeStoragePath::root())
                .await
                .unwrap()
                .root_path(),
            storage.root_path()
        );
    }

    #[tokio::test]
    async fn rejects_missing_or_non_directory_scopes() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("server.cfg"), "hostname open.mp").unwrap();
        let storage = LocalFileStorage::open(&directory.0, limits())
            .await
            .unwrap();

        let file = RelativeStoragePath::new("server.cfg").unwrap();
        assert!(matches!(
            storage.scoped(&file).await,
            Err(LocalFileStorageError::NotDirectory)
        ));

        let missing = RelativeStoragePath::new("missing").unwrap();
        assert!(matches!(
            storage.scoped(&missing).await,
            Err(LocalFileStorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound
        ));
    }

    #[tokio::test]
    async fn rejects_symbolic_link_roots_and_scopes() {
        let directory = TestDirectory::new();
        let target = directory.0.join("target");
        let link = directory.0.join("linked");
        fs::create_dir(&target).unwrap();

        if let Err(error) = create_directory_link(&target, &link) {
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("failed to create test symlink: {error}");
        }

        assert!(matches!(
            LocalFileStorage::open(&link, limits()).await,
            Err(LocalFileStorageError::LinkOrReparsePoint)
        ));

        let storage = LocalFileStorage::open(&directory.0, limits())
            .await
            .unwrap();
        let linked_scope = RelativeStoragePath::new("linked").unwrap();
        assert!(matches!(
            storage.scoped(&linked_scope).await,
            Err(LocalFileStorageError::LinkOrReparsePoint)
        ));
    }

    #[cfg(unix)]
    fn create_directory_link(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_directory_link(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }
}
