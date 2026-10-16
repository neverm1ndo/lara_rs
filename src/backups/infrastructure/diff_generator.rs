use std::time::Duration;

use diff_match_patch_rs::{Compat, DiffMatchPatch, PatchInput};
use encoding_rs::{Encoding, UTF_8, UTF_16BE, UTF_16LE, WINDOWS_1251};
use thiserror::Error;

use crate::backups::{
    application::ports::{
        BackupDiffError, BackupDiffFuture, BackupDiffGenerator, BackupDiffInput,
        skipped_binary_diff,
    },
    domain::{BackupDiff, BackupDiffSkipReason},
};

const UTF8_BOM: &[u8] = &[0xef, 0xbb, 0xbf];
const UTF16_LE_BOM: &[u8] = &[0xff, 0xfe];
const UTF16_BE_BOM: &[u8] = &[0xfe, 0xff];

/// Produces client-compatible Diff Match Patch text from decoded copies of
/// source bytes. Snapshot bytes themselves are never transcoded.
#[derive(Debug, Clone)]
pub struct DiffMatchPatchGenerator {
    enabled: bool,
    max_input_size_bytes: u64,
    generation_timeout: Duration,
    fallback_encoding: &'static Encoding,
}

impl DiffMatchPatchGenerator {
    pub fn new(
        enabled: bool,
        max_input_size_bytes: u64,
        generation_timeout: Duration,
        fallback_encoding: &'static Encoding,
    ) -> Result<Self, InvalidDiffMatchPatchGenerator> {
        if max_input_size_bytes == 0 {
            return Err(InvalidDiffMatchPatchGenerator::InputSize);
        }
        if generation_timeout.is_zero() || generation_timeout.as_millis() > u128::from(u32::MAX) {
            return Err(InvalidDiffMatchPatchGenerator::Timeout);
        }

        Ok(Self {
            enabled,
            max_input_size_bytes,
            generation_timeout,
            fallback_encoding,
        })
    }

    pub fn from_encoding_label(
        enabled: bool,
        max_input_size_bytes: u64,
        generation_timeout: Duration,
        fallback_encoding: &str,
    ) -> Result<Self, InvalidDiffMatchPatchGenerator> {
        let encoding = Encoding::for_label(fallback_encoding.as_bytes())
            .ok_or(InvalidDiffMatchPatchGenerator::Encoding)?;
        Self::new(enabled, max_input_size_bytes, generation_timeout, encoding)
    }

    fn exceeds_input_limit(&self, before: &[u8], after: Option<&[u8]>) -> bool {
        let total =
            (before.len() as u64).checked_add(after.map_or(0, |content| content.len() as u64));
        total.is_none_or(|total| total > self.max_input_size_bytes)
    }
}

impl BackupDiffGenerator for DiffMatchPatchGenerator {
    fn generate<'a>(&'a self, input: BackupDiffInput<'a>) -> BackupDiffFuture<'a> {
        Box::pin(async move {
            if input.content_kind.is_binary() {
                return Ok(skipped_binary_diff());
            }
            if !self.enabled {
                return Ok(BackupDiff::Skipped(BackupDiffSkipReason::Disabled));
            }
            if self.exceeds_input_limit(input.before, input.after) {
                return Ok(BackupDiff::Skipped(BackupDiffSkipReason::InputTooLarge));
            }

            let Some(before) = decode_text(input.before, self.fallback_encoding) else {
                return Ok(BackupDiff::Skipped(
                    BackupDiffSkipReason::UnsupportedEncoding,
                ));
            };
            let after = match input.after {
                Some(content) => {
                    let Some(decoded) = decode_text(content, self.fallback_encoding) else {
                        return Ok(BackupDiff::Skipped(
                            BackupDiffSkipReason::UnsupportedEncoding,
                        ));
                    };
                    decoded
                }
                None => String::new(),
            };

            let timeout = self.generation_timeout;
            let timeout_millis = u32::try_from(timeout.as_millis())
                .expect("constructor restricts timeout to u32 milliseconds");
            let task = tokio::task::spawn_blocking(move || {
                let mut dmp = DiffMatchPatch::new();
                dmp.set_timeout(Some(timeout_millis));
                let diffs = dmp
                    .diff_main::<Compat>(&before, &after)
                    .map_err(diff_error)?;
                let patches = dmp
                    .patch_make(PatchInput::new_diffs(&diffs))
                    .map_err(diff_error)?;
                Ok::<_, BackupDiffError>(dmp.patch_to_text(&patches))
            });

            match tokio::time::timeout(timeout, task).await {
                Err(_) => Ok(BackupDiff::Skipped(
                    BackupDiffSkipReason::GenerationTimedOut,
                )),
                Ok(Err(error)) => Err(BackupDiffError::Failed {
                    message: format!("diff worker failed: {error}"),
                }),
                Ok(Ok(result)) => result.map(BackupDiff::DiffMatchPatch),
            }
        })
    }
}

fn decode_text(content: &[u8], fallback: &'static Encoding) -> Option<String> {
    let (encoding, bytes, uses_fallback) = if let Some(content) = content.strip_prefix(UTF8_BOM) {
        (UTF_8, content, false)
    } else if let Some(content) = content.strip_prefix(UTF16_LE_BOM) {
        (UTF_16LE, content, false)
    } else if let Some(content) = content.strip_prefix(UTF16_BE_BOM) {
        (UTF_16BE, content, false)
    } else if std::str::from_utf8(content).is_ok() {
        (UTF_8, content, false)
    } else {
        (fallback, content, true)
    };

    // WHATWG maps the only unassigned Windows-1251 byte permissively to a
    // control character. Keep diff validation aligned with configuration
    // uploads and reject it explicitly.
    if uses_fallback && std::ptr::eq(encoding, WINDOWS_1251) && bytes.contains(&0x98) {
        return None;
    }

    encoding
        .decode_without_bom_handling_and_without_replacement(bytes)
        .map(|text| text.into_owned())
}

fn diff_error(error: diff_match_patch_rs::Error) -> BackupDiffError {
    BackupDiffError::Failed {
        message: format!("{error:?}"),
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidDiffMatchPatchGenerator {
    #[error("diff input size limit must be greater than zero")]
    InputSize,
    #[error("diff timeout must fit a positive u32 millisecond value")]
    Timeout,
    #[error("diff fallback encoding is unsupported")]
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backups::{
            application::ports::BackupDiffInput,
            domain::{BackupDiffSkipReason, BackupSource},
        },
        shared::file_storage::{
            content::FileContentKind, mutation::StorageNamespace, path::RelativeStoragePath,
        },
    };

    fn source() -> BackupSource {
        BackupSource::new(
            StorageNamespace::new("configuration").unwrap(),
            RelativeStoragePath::new("server.cfg").unwrap(),
        )
        .unwrap()
    }

    fn generator() -> DiffMatchPatchGenerator {
        DiffMatchPatchGenerator::from_encoding_label(
            true,
            1024 * 1024,
            Duration::from_secs(1),
            "windows-1251",
        )
        .unwrap()
    }

    async fn generate(
        generator: &DiffMatchPatchGenerator,
        kind: FileContentKind,
        before: &[u8],
        after: Option<&[u8]>,
    ) -> BackupDiff {
        let source = source();
        generator
            .generate(BackupDiffInput {
                source: &source,
                content_kind: kind,
                before,
                after,
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn creates_compatible_patch_for_windows_1251_text() {
        let encoding = Encoding::for_label(b"windows-1251").unwrap();
        let (before, _, _) = encoding.encode("hostname Старый сервер\r\n");
        let (after, _, _) = encoding.encode("hostname Новый сервер\r\n");

        let BackupDiff::DiffMatchPatch(patch_text) =
            generate(&generator(), FileContentKind::Text, &before, Some(&after)).await
        else {
            panic!("text diff was unexpectedly skipped");
        };

        let dmp = DiffMatchPatch::new();
        let patches = dmp.patch_from_text::<Compat>(&patch_text).unwrap();
        let (actual, applied) = dmp
            .patch_apply(&patches, "hostname Старый сервер\r\n")
            .unwrap();
        assert_eq!(actual, "hostname Новый сервер\r\n");
        assert!(applied.iter().all(|applied| *applied));
    }

    #[tokio::test]
    async fn detects_utf8_without_bom_before_using_legacy_fallback() {
        let before = "<map name=\"Старая\"/>".as_bytes();
        let after = "<map name=\"Новая\"/>".as_bytes();

        let BackupDiff::DiffMatchPatch(patch_text) =
            generate(&generator(), FileContentKind::Text, before, Some(after)).await
        else {
            panic!("UTF-8 diff was unexpectedly skipped");
        };

        let dmp = DiffMatchPatch::new();
        let patches = dmp.patch_from_text::<Compat>(&patch_text).unwrap();
        let (actual, applied) = dmp.patch_apply(&patches, "<map name=\"Старая\"/>").unwrap();

        assert_eq!(actual, "<map name=\"Новая\"/>");
        assert!(applied.into_iter().all(|value| value));
    }

    #[tokio::test]
    async fn recognizes_utf_boms_independently_of_fallback_encoding() {
        let before = [UTF8_BOM, "Привет".as_bytes()].concat();
        let utf16 = "Пока".encode_utf16().collect::<Vec<_>>();
        let mut after = UTF16_LE_BOM.to_vec();
        after.extend(utf16.into_iter().flat_map(u16::to_le_bytes));

        assert!(matches!(
            generate(&generator(), FileContentKind::Text, &before, Some(&after)).await,
            BackupDiff::DiffMatchPatch(_)
        ));
    }

    #[tokio::test]
    async fn deletion_generates_a_patch_to_an_empty_document() {
        let BackupDiff::DiffMatchPatch(patch) =
            generate(&generator(), FileContentKind::Text, b"remove me", None).await
        else {
            panic!("delete diff was unexpectedly skipped");
        };

        assert!(patch.contains("-remove me"));
    }

    #[tokio::test]
    async fn skips_binary_disabled_large_and_malformed_inputs() {
        let binary = generate(
            &generator(),
            FileContentKind::Binary,
            &[0, 1, 2],
            Some(&[3, 4]),
        )
        .await;
        assert_eq!(
            binary,
            BackupDiff::Skipped(BackupDiffSkipReason::BinaryContent)
        );

        let disabled = DiffMatchPatchGenerator::new(
            false,
            1024,
            Duration::from_secs(1),
            encoding_rs::WINDOWS_1251,
        )
        .unwrap();
        assert_eq!(
            generate(&disabled, FileContentKind::Text, b"old", Some(b"new")).await,
            BackupDiff::Skipped(BackupDiffSkipReason::Disabled)
        );

        let limited = DiffMatchPatchGenerator::new(
            true,
            5,
            Duration::from_secs(1),
            encoding_rs::WINDOWS_1251,
        )
        .unwrap();
        assert_eq!(
            generate(&limited, FileContentKind::Text, b"old", Some(b"new")).await,
            BackupDiff::Skipped(BackupDiffSkipReason::InputTooLarge)
        );

        assert_eq!(
            generate(&generator(), FileContentKind::Text, &[0x98], Some(b"valid"),).await,
            BackupDiff::Skipped(BackupDiffSkipReason::UnsupportedEncoding)
        );
    }

    #[test]
    fn validates_generator_configuration() {
        assert!(matches!(
            DiffMatchPatchGenerator::new(
                true,
                0,
                Duration::from_secs(1),
                encoding_rs::WINDOWS_1251,
            ),
            Err(InvalidDiffMatchPatchGenerator::InputSize)
        ));
        assert!(matches!(
            DiffMatchPatchGenerator::new(true, 1, Duration::ZERO, encoding_rs::WINDOWS_1251,),
            Err(InvalidDiffMatchPatchGenerator::Timeout)
        ));
        assert!(matches!(
            DiffMatchPatchGenerator::from_encoding_label(
                true,
                1,
                Duration::from_secs(1),
                "unknown-encoding",
            ),
            Err(InvalidDiffMatchPatchGenerator::Encoding)
        ));
    }
}
