use std::collections::HashSet;

use thiserror::Error;

use super::path::{RelativeStoragePath, StorageFileName};

const BYTE_TAB: u8 = 0x09;
const BYTE_LF: u8 = 0x0a;
const BYTE_CR: u8 = 0x0d;
const ASCII_PRINTABLE_START: u8 = 0x20;

const UTF8_BOM: &[u8] = &[0xef, 0xbb, 0xbf];
const UTF16_LE_BOM: &[u8] = &[0xff, 0xfe];
const UTF16_BE_BOM: &[u8] = &[0xfe, 0xff];

pub const DEFAULT_BINARY_SAMPLE_SIZE: usize = 512;
pub const DEFAULT_BINARY_THRESHOLD: f64 = 0.3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileContentKind {
    Text,
    Binary,
}

impl FileContentKind {
    pub const fn is_binary(self) -> bool {
        matches!(self, Self::Binary)
    }
}

/// Classifies opaque file bytes without decoding or transcoding them.
///
/// Explicit file-name and extension rules have priority. Unknown files are
/// classified from a bounded prefix so the decision cost does not grow with
/// the file size. Bytes above the ASCII range are treated as printable, which
/// keeps Windows-1251 configuration files eligible for textual diffs.
#[derive(Debug, Clone)]
pub struct FileContentClassifier {
    binary_extensions: HashSet<String>,
    binary_file_names: HashSet<String>,
    sample_size: usize,
    binary_threshold: f64,
}

impl FileContentClassifier {
    pub fn new(
        binary_extensions: impl IntoIterator<Item = impl Into<String>>,
        binary_file_names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, InvalidFileContentClassifier> {
        Self::with_heuristic(
            binary_extensions,
            binary_file_names,
            DEFAULT_BINARY_SAMPLE_SIZE,
            DEFAULT_BINARY_THRESHOLD,
        )
    }

    pub fn with_heuristic(
        binary_extensions: impl IntoIterator<Item = impl Into<String>>,
        binary_file_names: impl IntoIterator<Item = impl Into<String>>,
        sample_size: usize,
        binary_threshold: f64,
    ) -> Result<Self, InvalidFileContentClassifier> {
        if sample_size == 0 {
            return Err(InvalidFileContentClassifier::SampleSize);
        }
        if !binary_threshold.is_finite() || !(0.0..=1.0).contains(&binary_threshold) {
            return Err(InvalidFileContentClassifier::Threshold);
        }

        let mut extensions = HashSet::new();
        for extension in binary_extensions {
            let extension = extension.into();
            if extension.is_empty()
                || !extension
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            {
                return Err(InvalidFileContentClassifier::Extension(extension));
            }
            if !extensions.insert(extension.clone()) {
                return Err(InvalidFileContentClassifier::DuplicateExtension(extension));
            }
        }

        let mut names = HashSet::new();
        for name in binary_file_names {
            let name = name.into();
            if StorageFileName::new(name.clone()).is_err() {
                return Err(InvalidFileContentClassifier::FileName(name));
            }

            let normalized = name.to_ascii_lowercase();
            if !names.insert(normalized) {
                return Err(InvalidFileContentClassifier::DuplicateFileName(name));
            }
        }

        Ok(Self {
            binary_extensions: extensions,
            binary_file_names: names,
            sample_size,
            binary_threshold,
        })
    }

    pub fn classify(&self, path: &RelativeStoragePath, content: &[u8]) -> FileContentKind {
        if self.matches_explicit_binary_rule(path) || self.looks_binary(content) {
            FileContentKind::Binary
        } else {
            FileContentKind::Text
        }
    }

    fn matches_explicit_binary_rule(&self, path: &RelativeStoragePath) -> bool {
        let Some(file_name) = path.file_name() else {
            return false;
        };
        let normalized_name = file_name.to_ascii_lowercase();

        if self.binary_file_names.contains(&normalized_name) {
            return true;
        }

        normalized_name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| self.binary_extensions.contains(extension))
    }

    fn looks_binary(&self, content: &[u8]) -> bool {
        if content.is_empty() || has_text_bom(content) {
            return false;
        }

        let sample = &content[..content.len().min(self.sample_size)];
        let non_printable = sample
            .iter()
            .filter(|&&byte| {
                byte < ASCII_PRINTABLE_START && !matches!(byte, BYTE_TAB | BYTE_LF | BYTE_CR)
            })
            .count();

        non_printable as f64 / sample.len() as f64 > self.binary_threshold
    }
}

fn has_text_bom(content: &[u8]) -> bool {
    content.starts_with(UTF8_BOM)
        || content.starts_with(UTF16_LE_BOM)
        || content.starts_with(UTF16_BE_BOM)
}

#[derive(Debug, Clone, Error, PartialEq)]
pub enum InvalidFileContentClassifier {
    #[error("binary sample size must be greater than zero")]
    SampleSize,
    #[error("binary threshold must be a finite number between zero and one")]
    Threshold,
    #[error("binary extension is invalid: {0}")]
    Extension(String),
    #[error("binary extension is duplicated: {0}")]
    DuplicateExtension(String),
    #[error("binary file name is invalid: {0}")]
    FileName(String),
    #[error("binary file name is duplicated ignoring ASCII case: {0}")]
    DuplicateFileName(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    fn classifier() -> FileContentClassifier {
        FileContentClassifier::new(
            ["amx", "dff", "dll", "exe", "so", "txd"],
            ["omp-server", "samp03svr"],
        )
        .unwrap()
    }

    #[test]
    fn explicit_binary_rules_have_priority_and_are_case_insensitive() {
        let classifier = classifier();

        for binary in [
            "gamemodes/RACE.AMX",
            "models/car.TXD",
            "plugins/native.SO",
            "OMP-SERVER",
        ] {
            assert_eq!(
                classifier.classify(&path(binary), b"plain textual bytes"),
                FileContentKind::Binary
            );
        }
    }

    #[test]
    fn recognizes_empty_ascii_and_windows_1251_as_text() {
        let classifier = classifier();
        let windows_1251 = [0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2];

        for content in [b"".as_slice(), b"hostname open.mp\r\n", &windows_1251] {
            assert_eq!(
                classifier.classify(&path("server.cfg"), content),
                FileContentKind::Text
            );
        }
    }

    #[test]
    fn recognizes_control_heavy_unknown_content_as_binary() {
        let classifier = classifier();
        let mut content = vec![b'a'; DEFAULT_BINARY_SAMPLE_SIZE];
        content[..155].fill(0);

        assert_eq!(
            classifier.classify(&path("unknown.data"), &content),
            FileContentKind::Binary
        );

        content[..155].fill(b'a');
        content[..153].fill(0);
        assert_eq!(
            classifier.classify(&path("unknown.data"), &content),
            FileContentKind::Text
        );
    }

    #[test]
    fn allows_common_text_controls_and_honors_text_boms() {
        let classifier = classifier();

        assert_eq!(
            classifier.classify(&path("tabs.cfg"), b"\t\r\n\t\r\n"),
            FileContentKind::Text
        );
        for bom in [UTF8_BOM, UTF16_LE_BOM, UTF16_BE_BOM] {
            let content = [bom, &[0; 32]].concat();
            assert_eq!(
                classifier.classify(&path("encoded.cfg"), &content),
                FileContentKind::Text
            );
        }
    }

    #[test]
    fn inspects_only_the_configured_prefix() {
        let classifier = FileContentClassifier::with_heuristic(
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
            4,
            0.3,
        )
        .unwrap();
        let content = [b"text".as_slice(), &[0; 128]].concat();

        assert_eq!(
            classifier.classify(&path("sample.unknown"), &content),
            FileContentKind::Text
        );
    }

    #[test]
    fn validates_rules_and_heuristic_parameters() {
        assert!(matches!(
            FileContentClassifier::with_heuristic([".amx"], std::iter::empty::<String>(), 512, 0.3,),
            Err(InvalidFileContentClassifier::Extension(_))
        ));
        assert!(matches!(
            FileContentClassifier::new(["amx", "amx"], std::iter::empty::<String>()),
            Err(InvalidFileContentClassifier::DuplicateExtension(_))
        ));
        assert!(matches!(
            FileContentClassifier::new(std::iter::empty::<String>(), ["omp-server", "OMP-SERVER"],),
            Err(InvalidFileContentClassifier::DuplicateFileName(_))
        ));
        assert!(matches!(
            FileContentClassifier::with_heuristic(
                std::iter::empty::<String>(),
                std::iter::empty::<String>(),
                0,
                0.3,
            ),
            Err(InvalidFileContentClassifier::SampleSize)
        ));
        assert!(matches!(
            FileContentClassifier::with_heuristic(
                std::iter::empty::<String>(),
                std::iter::empty::<String>(),
                512,
                f64::NAN,
            ),
            Err(InvalidFileContentClassifier::Threshold)
        ));
    }
}
