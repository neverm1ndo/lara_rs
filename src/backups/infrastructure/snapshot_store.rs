use std::{io, path::Path, path::PathBuf, pin::Pin, sync::Arc};

use async_compression::{
    Level,
    tokio::{bufread::GzipDecoder, write::GzipEncoder},
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use crate::{
    backups::{
        application::ports::{
            BackupSnapshotReader, BackupSnapshotStore, BackupSnapshotStoreError,
            BackupSnapshotStoreFuture, BackupSnapshotWrite, OpenedBackupSnapshot,
            StoredBackupSnapshot,
        },
        domain::{BackupId, SnapshotCompression},
    },
    shared::file_storage::mutation::{ContentHashAlgorithm, FileContentHash},
};

/// Filesystem snapshot adapter confined to one private canonical directory.
/// Snapshot names are generated exclusively from typed UUIDs.
#[derive(Debug, Clone)]
pub struct LocalBackupSnapshotStore {
    root: Arc<PathBuf>,
    gzip_level: u32,
}

impl LocalBackupSnapshotStore {
    pub async fn initialize(
        root: impl AsRef<Path>,
        gzip_level: u32,
    ) -> Result<Self, LocalBackupSnapshotStoreError> {
        if gzip_level > 9 {
            return Err(LocalBackupSnapshotStoreError::InvalidGzipLevel);
        }

        let requested = absolute_path(root.as_ref())?;
        match tokio::fs::symlink_metadata(&requested).await {
            Ok(metadata) if is_link_or_reparse_point(&metadata) => {
                return Err(LocalBackupSnapshotStoreError::LinkOrReparsePoint);
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(LocalBackupSnapshotStoreError::NotDirectory);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                tokio::fs::create_dir_all(&requested).await?;
            }
            Err(error) => return Err(error.into()),
        }
        let metadata = tokio::fs::symlink_metadata(&requested).await?;
        if is_link_or_reparse_point(&metadata) {
            return Err(LocalBackupSnapshotStoreError::LinkOrReparsePoint);
        }
        if !metadata.is_dir() {
            return Err(LocalBackupSnapshotStoreError::NotDirectory);
        }

        Ok(Self {
            root: Arc::new(tokio::fs::canonicalize(requested).await?),
            gzip_level,
        })
    }

    fn snapshot_path(&self, backup_id: BackupId) -> PathBuf {
        self.root.join(backup_id.to_string())
    }

    fn temporary_path(&self, backup_id: BackupId) -> PathBuf {
        self.root.join(format!(
            ".{}.{}.tmp",
            backup_id,
            Uuid::new_v4().as_hyphenated()
        ))
    }

    async fn write_temporary(
        &self,
        path: &Path,
        content: &[u8],
        compression: SnapshotCompression,
    ) -> io::Result<()> {
        let mut options = tokio::fs::OpenOptions::new();
        let file = options.write(true).create_new(true).open(path).await?;

        match compression {
            SnapshotCompression::None => {
                let mut file = file;
                file.write_all(content).await?;
                file.flush().await?;
                file.sync_all().await?;
            }
            SnapshotCompression::Gzip => {
                let mut encoder = GzipEncoder::with_quality(
                    file,
                    Level::Precise(i32::try_from(self.gzip_level).expect("level is at most nine")),
                );
                encoder.write_all(content).await?;
                encoder.shutdown().await?;
                encoder.get_mut().sync_all().await?;
            }
        }

        Ok(())
    }

    async fn publish_temporary(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), BackupSnapshotStoreError> {
        match tokio::fs::hard_link(temporary, destination).await {
            Ok(()) => {
                tokio::fs::remove_file(temporary)
                    .await
                    .map_err(unavailable)?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = tokio::fs::remove_file(temporary).await;
                Err(BackupSnapshotStoreError::AlreadyExists)
            }
            Err(error) => {
                let _ = tokio::fs::remove_file(temporary).await;
                Err(unavailable(error))
            }
        }
    }

    async fn verified_reader(
        &self,
        backup_id: BackupId,
        expected_hash: &FileContentHash,
        compression: SnapshotCompression,
    ) -> Result<OpenedBackupSnapshot, BackupSnapshotStoreError> {
        let path = self.snapshot_path(backup_id);
        validate_regular_snapshot(&path).await?;

        let (actual_hash, original_bytes) = hash_reader(open_reader(&path, compression).await?)
            .await
            .map_err(unavailable)?;
        if &actual_hash != expected_hash {
            return Err(BackupSnapshotStoreError::IntegrityMismatch);
        }

        Ok(OpenedBackupSnapshot {
            reader: open_reader(&path, compression).await?,
            original_bytes,
            content_hash: actual_hash,
        })
    }
}

impl BackupSnapshotStore for LocalBackupSnapshotStore {
    fn persist<'a>(
        &'a self,
        write: BackupSnapshotWrite<'a>,
    ) -> BackupSnapshotStoreFuture<'a, StoredBackupSnapshot> {
        Box::pin(async move {
            let destination = self.snapshot_path(write.backup_id);
            match tokio::fs::symlink_metadata(&destination).await {
                Ok(_) => return Err(BackupSnapshotStoreError::AlreadyExists),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(unavailable(error)),
            }

            let temporary = self.temporary_path(write.backup_id);
            if let Err(error) = self
                .write_temporary(&temporary, write.content, write.compression)
                .await
            {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(unavailable(error));
            }
            let stored_bytes = tokio::fs::metadata(&temporary)
                .await
                .map_err(unavailable)?
                .len();
            self.publish_temporary(&temporary, &destination).await?;

            Ok(StoredBackupSnapshot {
                stored_bytes,
                content_hash: hash_bytes(write.content),
                compression: write.compression,
            })
        })
    }

    fn open<'a>(
        &'a self,
        backup_id: BackupId,
        expected_hash: &'a FileContentHash,
        compression: SnapshotCompression,
    ) -> BackupSnapshotStoreFuture<'a, OpenedBackupSnapshot> {
        Box::pin(async move {
            self.verified_reader(backup_id, expected_hash, compression)
                .await
        })
    }

    fn remove<'a>(&'a self, backup_id: BackupId) -> BackupSnapshotStoreFuture<'a, ()> {
        Box::pin(async move {
            let path = self.snapshot_path(backup_id);
            match tokio::fs::symlink_metadata(&path).await {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(unavailable(error)),
                Ok(metadata) if is_link_or_reparse_point(&metadata) || !metadata.is_file() => {
                    Err(BackupSnapshotStoreError::Unavailable {
                        message: "snapshot path is not a regular file".into(),
                    })
                }
                Ok(_) => tokio::fs::remove_file(path).await.map_err(unavailable),
            }
        })
    }
}

async fn validate_regular_snapshot(path: &Path) -> Result<(), BackupSnapshotStoreError> {
    match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(BackupSnapshotStoreError::NotFound)
        }
        Err(error) => Err(unavailable(error)),
        Ok(metadata) if is_link_or_reparse_point(&metadata) || !metadata.is_file() => {
            Err(BackupSnapshotStoreError::Unavailable {
                message: "snapshot path is not a regular file".into(),
            })
        }
        Ok(_) => Ok(()),
    }
}

async fn open_reader(
    path: &Path,
    compression: SnapshotCompression,
) -> Result<BackupSnapshotReader, BackupSnapshotStoreError> {
    let file = tokio::fs::File::open(path).await.map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            BackupSnapshotStoreError::NotFound
        } else {
            unavailable(error)
        }
    })?;
    let buffered = BufReader::new(file);

    Ok(match compression {
        SnapshotCompression::None => Box::pin(buffered),
        SnapshotCompression::Gzip => Box::pin(GzipDecoder::new(buffered)),
    })
}

async fn hash_reader(
    mut reader: Pin<Box<dyn AsyncRead + Send>>,
) -> io::Result<(FileContentHash, u64)> {
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("snapshot size overflow"))?;
    }

    Ok((hash_digest(digest.finalize()), total))
}

fn hash_bytes(content: &[u8]) -> FileContentHash {
    hash_digest(Sha256::digest(content))
}

fn hash_digest(digest: impl AsRef<[u8]>) -> FileContentHash {
    let hex = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    FileContentHash::new(ContentHashAlgorithm::Sha256, hex)
        .expect("SHA-256 always produces a valid 64-character hexadecimal digest")
}

fn unavailable(error: io::Error) -> BackupSnapshotStoreError {
    BackupSnapshotStoreError::Unavailable {
        message: error.to_string(),
    }
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
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
pub enum LocalBackupSnapshotStoreError {
    #[error("gzip compression level must be between zero and nine")]
    InvalidGzipLevel,
    #[error("backup snapshot root is not a directory")]
    NotDirectory,
    #[error("backup snapshot root cannot be a symbolic link or reparse point")]
    LinkOrReparsePoint,
    #[error("backup snapshot storage I/O error")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("lara-backup-snapshots-{}", Uuid::new_v4())))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn store(directory: &TestDirectory) -> LocalBackupSnapshotStore {
        LocalBackupSnapshotStore::initialize(&directory.0, 1)
            .await
            .unwrap()
    }

    async fn read_all(mut snapshot: OpenedBackupSnapshot) -> Vec<u8> {
        let mut content = Vec::new();
        snapshot.reader.read_to_end(&mut content).await.unwrap();
        content
    }

    #[tokio::test]
    async fn creates_private_root_and_round_trips_opaque_bytes() {
        let directory = TestDirectory::new();
        let store = store(&directory).await;
        let id = BackupId::new();
        let content = [0x00, 0xff, 0xcf, 0xf0, 0xe8, 0xe2];

        let stored = store
            .persist(BackupSnapshotWrite {
                backup_id: id,
                content: &content,
                compression: SnapshotCompression::None,
            })
            .await
            .unwrap();
        let opened = store
            .open(id, &stored.content_hash, stored.compression)
            .await
            .unwrap();

        assert_eq!(opened.original_bytes, content.len() as u64);
        assert_eq!(read_all(opened).await, content);
        assert_eq!(fs::read(directory.0.join(id.to_string())).unwrap(), content);
    }

    #[tokio::test]
    async fn gzip_is_transparent_and_uses_less_space_for_repetitive_content() {
        let directory = TestDirectory::new();
        let store = store(&directory).await;
        let id = BackupId::new();
        let content = vec![b'a'; 16 * 1024];

        let stored = store
            .persist(BackupSnapshotWrite {
                backup_id: id,
                content: &content,
                compression: SnapshotCompression::Gzip,
            })
            .await
            .unwrap();
        assert!(stored.stored_bytes < content.len() as u64);

        let opened = store
            .open(id, &stored.content_hash, stored.compression)
            .await
            .unwrap();
        assert_eq!(read_all(opened).await, content);
    }

    #[tokio::test]
    async fn refuses_hash_mismatch_and_never_overwrites_existing_snapshot() {
        let directory = TestDirectory::new();
        let store = store(&directory).await;
        let id = BackupId::new();
        let first = store
            .persist(BackupSnapshotWrite {
                backup_id: id,
                content: b"first",
                compression: SnapshotCompression::None,
            })
            .await
            .unwrap();

        assert_eq!(
            store
                .persist(BackupSnapshotWrite {
                    backup_id: id,
                    content: b"second",
                    compression: SnapshotCompression::None,
                })
                .await,
            Err(BackupSnapshotStoreError::AlreadyExists)
        );
        let wrong_hash = hash_bytes(b"wrong");
        assert!(matches!(
            store.open(id, &wrong_hash, first.compression).await,
            Err(BackupSnapshotStoreError::IntegrityMismatch)
        ));
        assert_eq!(
            read_all(
                store
                    .open(id, &first.content_hash, first.compression)
                    .await
                    .unwrap()
            )
            .await,
            b"first"
        );
    }

    #[tokio::test]
    async fn removal_is_idempotent_and_missing_open_is_typed() {
        let directory = TestDirectory::new();
        let store = store(&directory).await;
        let id = BackupId::new();
        let hash = hash_bytes(b"missing");

        store.remove(id).await.unwrap();
        assert!(matches!(
            store.open(id, &hash, SnapshotCompression::None).await,
            Err(BackupSnapshotStoreError::NotFound)
        ));

        store
            .persist(BackupSnapshotWrite {
                backup_id: id,
                content: b"present",
                compression: SnapshotCompression::None,
            })
            .await
            .unwrap();
        store.remove(id).await.unwrap();
        store.remove(id).await.unwrap();
        assert!(!directory.0.join(id.to_string()).exists());
    }

    #[tokio::test]
    async fn rejects_invalid_level_and_non_directory_root() {
        let directory = TestDirectory::new();
        assert!(matches!(
            LocalBackupSnapshotStore::initialize(&directory.0, 10).await,
            Err(LocalBackupSnapshotStoreError::InvalidGzipLevel)
        ));

        fs::create_dir_all(&directory.0).unwrap();
        let file = directory.0.join("file");
        fs::write(&file, b"not a directory").unwrap();
        assert!(matches!(
            LocalBackupSnapshotStore::initialize(file, 1).await,
            Err(LocalBackupSnapshotStoreError::NotDirectory)
        ));
    }
}
