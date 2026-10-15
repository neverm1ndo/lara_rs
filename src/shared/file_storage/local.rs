use std::{
    future::Future,
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    guard::{FileSnapshot, FileSnapshotSource, ReadFileSnapshotError, ReadFileSnapshotFuture},
    mutation::FileRevision,
    path::{RelativeStoragePath, StorageFileName},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageTreeEntryKind {
    Directory,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageTreeEntry {
    path: RelativeStoragePath,
    name: String,
    kind: StorageTreeEntryKind,
    size: Option<u64>,
    modified_at: Option<DateTime<Utc>>,
    children: Vec<StorageTreeEntry>,
}

impl StorageTreeEntry {
    pub fn path(&self) -> &RelativeStoragePath {
        &self.path
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> StorageTreeEntryKind {
        self.kind
    }

    pub fn size(&self) -> Option<u64> {
        self.size
    }

    pub fn modified_at(&self) -> Option<DateTime<Utc>> {
        self.modified_at
    }

    pub fn children(&self) -> &[StorageTreeEntry] {
        &self.children
    }

    pub fn into_children(self) -> Vec<StorageTreeEntry> {
        self.children
    }
}

pub struct OpenedStorageFile {
    pub reader: Pin<Box<dyn AsyncRead + Send>>,
    pub content_length: u64,
    pub revision: FileRevision,
}

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

    /// Builds a deterministic recursive tree inside this capability. Unsafe
    /// names and link/reparse-point entries are omitted rather than followed.
    pub async fn tree(&self) -> Result<Vec<StorageTreeEntry>, LocalFileStorageError> {
        let mut entry_count = 0_usize;
        self.read_tree_directory(
            self.root.as_ref().clone(),
            RelativeStoragePath::root(),
            0,
            &mut entry_count,
        )
        .await
    }

    /// Opens a regular file as an opaque, length-bounded byte stream.
    pub async fn open_file(
        &self,
        path: &RelativeStoragePath,
    ) -> Result<OpenedStorageFile, LocalFileStorageError> {
        let target = self.resolve_existing_file(path).await?;
        let file = tokio::fs::File::open(target).await?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() {
            return Err(LocalFileStorageError::NotFile);
        }
        if metadata.len() > self.limits.max_stream_size_bytes {
            return Err(LocalFileStorageError::ContentTooLarge {
                maximum: self.limits.max_stream_size_bytes,
            });
        }

        let modified_at = metadata.modified()?.into();
        let revision = FileRevision::from_metadata(metadata.len(), modified_at);
        let content_length = metadata.len();
        Ok(OpenedStorageFile {
            reader: Box::pin(file.take(content_length)),
            content_length,
            revision,
        })
    }

    fn read_tree_directory<'a>(
        &'a self,
        absolute_directory: PathBuf,
        relative_directory: RelativeStoragePath,
        depth: usize,
        entry_count: &'a mut usize,
    ) -> Pin<
        Box<dyn Future<Output = Result<Vec<StorageTreeEntry>, LocalFileStorageError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut directory = tokio::fs::read_dir(absolute_directory).await?;
            let mut entries = Vec::new();

            while let Some(entry) = directory.next_entry().await? {
                let Some(raw_name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                    continue;
                };
                let Ok(name) = StorageFileName::new(&raw_name) else {
                    continue;
                };
                let metadata = tokio::fs::symlink_metadata(entry.path()).await?;
                if is_link_or_reparse_point(&metadata) {
                    continue;
                }

                let kind = if metadata.is_dir() {
                    StorageTreeEntryKind::Directory
                } else if metadata.is_file() {
                    StorageTreeEntryKind::File
                } else {
                    continue;
                };

                if *entry_count >= self.limits.max_tree_entries {
                    return Err(LocalFileStorageError::TreeEntryLimitExceeded {
                        maximum: self.limits.max_tree_entries,
                    });
                }
                *entry_count += 1;

                let path = relative_directory.join(&name);
                let (size, modified_at, children) = match kind {
                    StorageTreeEntryKind::Directory => {
                        let child_depth = depth + 1;
                        if child_depth >= self.limits.max_tree_depth {
                            return Err(LocalFileStorageError::TreeDepthLimitExceeded {
                                maximum: self.limits.max_tree_depth,
                            });
                        }
                        let children = self
                            .read_tree_directory(
                                entry.path(),
                                path.clone(),
                                child_depth,
                                entry_count,
                            )
                            .await?;
                        (None, None, children)
                    }
                    StorageTreeEntryKind::File => {
                        let modified_at = Some(metadata.modified()?.into());
                        (Some(metadata.len()), modified_at, Vec::new())
                    }
                };

                entries.push(StorageTreeEntry {
                    path,
                    name: raw_name,
                    kind,
                    size,
                    modified_at,
                    children,
                });
            }

            entries.sort_by(|left, right| {
                left.kind.cmp(&right.kind).then_with(|| {
                    left.name
                        .to_ascii_lowercase()
                        .cmp(&right.name.to_ascii_lowercase())
                        .then_with(|| left.name.cmp(&right.name))
                })
            });
            Ok(entries)
        })
    }

    pub(super) async fn file_revision(
        &self,
        path: &RelativeStoragePath,
    ) -> Result<FileRevision, LocalFileStorageError> {
        let target = self.resolve_existing_file(path).await?;
        let metadata = tokio::fs::metadata(target).await?;
        let modified_at = metadata.modified()?.into();
        Ok(FileRevision::from_metadata(metadata.len(), modified_at))
    }

    pub(super) async fn ensure_absent(
        &self,
        path: &RelativeStoragePath,
    ) -> Result<(), LocalFileStorageError> {
        let target = self.resolve_new_file(path).await?;
        match tokio::fs::symlink_metadata(target).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err(LocalFileStorageError::AlreadyExists),
        }
    }

    pub(super) async fn create_file(
        &self,
        path: &RelativeStoragePath,
        content: &[u8],
    ) -> Result<(), LocalFileStorageError> {
        let target = self.resolve_new_file(path).await?;
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options.open(target).await?;
        use tokio::io::AsyncWriteExt;
        file.write_all(content).await?;
        file.flush().await?;
        Ok(())
    }

    pub(super) async fn overwrite_file(
        &self,
        path: &RelativeStoragePath,
        content: &[u8],
    ) -> Result<(), LocalFileStorageError> {
        let target = self.resolve_existing_file(path).await?;
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).truncate(true);
        let mut file = options.open(target).await?;
        use tokio::io::AsyncWriteExt;
        file.write_all(content).await?;
        file.flush().await?;
        Ok(())
    }

    pub(super) async fn delete_file(
        &self,
        path: &RelativeStoragePath,
    ) -> Result<(), LocalFileStorageError> {
        let target = self.resolve_existing_file(path).await?;
        tokio::fs::remove_file(target).await?;
        Ok(())
    }

    pub(super) async fn rename_file(
        &self,
        source: &RelativeStoragePath,
        destination: &RelativeStoragePath,
    ) -> Result<(), LocalFileStorageError> {
        let source = self.resolve_existing_file(source).await?;
        let destination = self.resolve_new_file(destination).await?;
        match tokio::fs::symlink_metadata(&destination).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(LocalFileStorageError::AlreadyExists),
        }
        tokio::fs::rename(source, destination).await?;
        Ok(())
    }

    async fn resolve_existing_file(
        &self,
        path: &RelativeStoragePath,
    ) -> Result<PathBuf, LocalFileStorageError> {
        let target = self.resolve_new_file(path).await?;
        let metadata = tokio::fs::symlink_metadata(&target).await?;
        if is_link_or_reparse_point(&metadata) {
            return Err(LocalFileStorageError::LinkOrReparsePoint);
        }
        if !metadata.is_file() {
            return Err(LocalFileStorageError::NotFile);
        }
        Ok(target)
    }

    async fn resolve_new_file(
        &self,
        path: &RelativeStoragePath,
    ) -> Result<PathBuf, LocalFileStorageError> {
        if path.is_root() {
            return Err(LocalFileStorageError::RootFile);
        }

        let parent = path.parent().expect("non-root path has a parent");
        let mut resolved_parent = self.root.as_ref().clone();
        for component in parent.components() {
            resolved_parent.push(component);
            let metadata = tokio::fs::symlink_metadata(&resolved_parent).await?;
            if is_link_or_reparse_point(&metadata) {
                return Err(LocalFileStorageError::LinkOrReparsePoint);
            }
            if !metadata.is_dir() {
                return Err(LocalFileStorageError::NotDirectory);
            }
        }

        let canonical_parent = tokio::fs::canonicalize(&resolved_parent).await?;
        if !canonical_parent.starts_with(self.root.as_ref()) {
            return Err(LocalFileStorageError::OutsideRoot);
        }

        Ok(canonical_parent.join(path.file_name().expect("non-root path has a name")))
    }

    #[cfg(test)]
    fn root_path(&self) -> &Path {
        self.root.as_path()
    }
}

impl FileSnapshotSource for LocalFileStorage {
    fn read_verified<'a>(&'a self, snapshot: &'a FileSnapshot) -> ReadFileSnapshotFuture<'a> {
        Box::pin(async move {
            if snapshot.revision().size() > self.limits.max_stream_size_bytes {
                return Err(ReadFileSnapshotError::ContentTooLarge);
            }

            let before = self
                .file_revision(snapshot.path())
                .await
                .map_err(snapshot_read_error)?;
            if &before != snapshot.revision() {
                return Err(ReadFileSnapshotError::Changed);
            }

            let target = self
                .resolve_existing_file(snapshot.path())
                .await
                .map_err(snapshot_read_error)?;
            let content = tokio::fs::read(target)
                .await
                .map_err(|error| snapshot_read_error(error.into()))?;
            if content.len() as u64 > self.limits.max_stream_size_bytes {
                return Err(ReadFileSnapshotError::ContentTooLarge);
            }

            let after = self
                .file_revision(snapshot.path())
                .await
                .map_err(snapshot_read_error)?;
            if before != after
                || &after != snapshot.revision()
                || after.size() != content.len() as u64
            {
                return Err(ReadFileSnapshotError::Changed);
            }

            Ok(content)
        })
    }
}

fn snapshot_read_error(error: LocalFileStorageError) -> ReadFileSnapshotError {
    match error {
        LocalFileStorageError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            ReadFileSnapshotError::Changed
        }
        _ => ReadFileSnapshotError::Unavailable,
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
    #[error("file-storage path is not a regular file")]
    NotFile,
    #[error("the file-storage capability root cannot be used as a file")]
    RootFile,
    #[error("the destination already exists")]
    AlreadyExists,
    #[error("file tree exceeds the configured depth limit of {maximum}")]
    TreeDepthLimitExceeded { maximum: usize },
    #[error("file tree exceeds the configured entry limit of {maximum}")]
    TreeEntryLimitExceeded { maximum: usize },
    #[error("file exceeds the configured {maximum}-byte stream limit")]
    ContentTooLarge { maximum: u64 },
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

    #[tokio::test]
    async fn builds_a_recursive_deterministic_tree_with_metadata() {
        let directory = TestDirectory::new();
        fs::create_dir_all(directory.0.join("city").join("interiors")).unwrap();
        fs::write(directory.0.join("z.map"), b"root").unwrap();
        fs::write(directory.0.join("city").join("race.map"), b"race").unwrap();
        fs::write(
            directory
                .0
                .join("city")
                .join("interiors")
                .join("shop.map.off"),
            b"shop",
        )
        .unwrap();

        let storage = LocalFileStorage::open(&directory.0, limits())
            .await
            .unwrap();
        let tree = storage.tree().await.unwrap();

        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].name(), "city");
        assert_eq!(tree[0].kind(), StorageTreeEntryKind::Directory);
        assert_eq!(tree[0].path().to_string(), "city");
        assert_eq!(tree[0].children()[0].name(), "interiors");
        assert_eq!(
            tree[0].children()[0].children()[0].path().to_string(),
            "city/interiors/shop.map.off"
        );
        assert_eq!(tree[0].children()[1].path().to_string(), "city/race.map");
        assert_eq!(tree[0].children()[1].size(), Some(4));
        assert!(tree[0].children()[1].modified_at().is_some());
        assert_eq!(tree[1].name(), "z.map");
    }

    #[tokio::test]
    async fn enforces_tree_depth_and_entry_limits() {
        let directory = TestDirectory::new();
        fs::create_dir_all(directory.0.join("nested")).unwrap();
        fs::write(directory.0.join("one.map"), b"1").unwrap();
        fs::write(directory.0.join("two.map"), b"2").unwrap();

        let shallow =
            LocalFileStorage::open(&directory.0, FileStorageLimits::new(1, 100, 1024).unwrap())
                .await
                .unwrap();
        assert!(matches!(
            shallow.tree().await,
            Err(LocalFileStorageError::TreeDepthLimitExceeded { maximum: 1 })
        ));

        let limited =
            LocalFileStorage::open(&directory.0, FileStorageLimits::new(8, 2, 1024).unwrap())
                .await
                .unwrap();
        assert!(matches!(
            limited.tree().await,
            Err(LocalFileStorageError::TreeEntryLimitExceeded { maximum: 2 })
        ));
    }

    #[tokio::test]
    async fn ignores_links_while_building_the_tree() {
        let directory = TestDirectory::new();
        let target = directory.0.join("target");
        let link = directory.0.join("linked");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("map.map"), b"map").unwrap();

        if let Err(error) = create_directory_link(&target, &link) {
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("failed to create test symlink: {error}");
        }

        let storage = LocalFileStorage::open(&directory.0, limits())
            .await
            .unwrap();
        let tree = storage.tree().await.unwrap();

        assert!(tree.iter().any(|entry| entry.name() == "target"));
        assert!(!tree.iter().any(|entry| entry.name() == "linked"));
    }

    #[tokio::test]
    async fn opens_an_opaque_length_bounded_file_stream() {
        let directory = TestDirectory::new();
        let bytes = vec![0x00, 0xff, 0x98, 0x10];
        fs::write(directory.0.join("binary.map"), &bytes).unwrap();
        let storage = LocalFileStorage::open(&directory.0, limits())
            .await
            .unwrap();
        let path = RelativeStoragePath::new("binary.map").unwrap();

        let mut opened = storage.open_file(&path).await.unwrap();
        let mut actual = Vec::new();
        opened.reader.read_to_end(&mut actual).await.unwrap();

        assert_eq!(actual, bytes);
        assert_eq!(opened.content_length, 4);
        assert_eq!(opened.revision.size(), 4);
    }

    #[tokio::test]
    async fn refuses_to_stream_files_above_the_configured_limit() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("large.map"), b"12345").unwrap();
        let storage =
            LocalFileStorage::open(&directory.0, FileStorageLimits::new(8, 100, 4).unwrap())
                .await
                .unwrap();

        assert!(matches!(
            storage
                .open_file(&RelativeStoragePath::new("large.map").unwrap())
                .await,
            Err(LocalFileStorageError::ContentTooLarge { maximum: 4 })
        ));
    }

    #[tokio::test]
    async fn reads_only_the_verified_snapshot_bytes() {
        let directory = TestDirectory::new();
        let cp1251 = vec![0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2];
        fs::write(directory.0.join("server.cfg"), &cp1251).unwrap();
        let storage = LocalFileStorage::open(&directory.0, limits())
            .await
            .unwrap();
        let path = RelativeStoragePath::new("server.cfg").unwrap();
        let revision = storage.file_revision(&path).await.unwrap();
        let snapshot = FileSnapshot::new(path.clone(), revision).unwrap();

        assert_eq!(storage.read_verified(&snapshot).await.unwrap(), cp1251);

        fs::write(directory.0.join("server.cfg"), b"changed-content").unwrap();
        assert_eq!(
            storage.read_verified(&snapshot).await,
            Err(ReadFileSnapshotError::Changed)
        );
    }

    #[tokio::test]
    async fn refuses_to_materialize_a_snapshot_above_the_read_limit() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("server.cfg"), b"12345").unwrap();
        let storage =
            LocalFileStorage::open(&directory.0, FileStorageLimits::new(8, 100, 4).unwrap())
                .await
                .unwrap();
        let path = RelativeStoragePath::new("server.cfg").unwrap();
        let revision = storage.file_revision(&path).await.unwrap();
        let snapshot = FileSnapshot::new(path, revision).unwrap();

        assert_eq!(
            storage.read_verified(&snapshot).await,
            Err(ReadFileSnapshotError::ContentTooLarge)
        );
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
