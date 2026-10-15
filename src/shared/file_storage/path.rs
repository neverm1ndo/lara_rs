use std::{
    fmt,
    path::{Path, PathBuf},
};

use thiserror::Error;

/// A normalized, portable path relative to a file-storage capability root.
///
/// Both slash styles are treated as separators so a value accepted on Linux
/// cannot become a traversal path when the same configuration is used on
/// Windows. The empty value is reserved for [`Self::root`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelativeStoragePath {
    components: Vec<String>,
}

impl RelativeStoragePath {
    pub fn root() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    pub fn new(value: impl AsRef<str>) -> Result<Self, InvalidStoragePath> {
        parse_components(value.as_ref()).map(|components| Self { components })
    }

    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    pub fn join(&self, name: &StorageFileName) -> Self {
        let mut components = self.components.clone();
        components.push(name.value.clone());
        Self { components }
    }

    pub fn join_path(&self, suffix: &Self) -> Self {
        let mut components = self.components.clone();
        components.extend(suffix.components.iter().cloned());
        Self { components }
    }

    /// Returns true for the path itself and all of its descendants. ASCII
    /// case-insensitive comparison keeps access rules portable to Windows.
    pub fn is_within_case_insensitive(&self, ancestor: &Self) -> bool {
        self.components.len() >= ancestor.components.len()
            && self
                .components
                .iter()
                .zip(&ancestor.components)
                .all(|(component, expected)| component.eq_ignore_ascii_case(expected))
    }

    pub fn parent(&self) -> Option<Self> {
        let mut components = self.components.clone();
        components.pop()?;
        Some(Self { components })
    }

    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    pub fn as_normalized_str(&self) -> String {
        self.components.join("/")
    }

    pub fn to_path_buf(&self) -> PathBuf {
        self.components.iter().collect()
    }

    pub(crate) fn components(&self) -> impl Iterator<Item = &str> {
        self.components.iter().map(String::as_str)
    }
}

impl fmt::Display for RelativeStoragePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_normalized_str())
    }
}

impl TryFrom<&Path> for RelativeStoragePath {
    type Error = InvalidStoragePath;

    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        let value = value.to_str().ok_or(InvalidStoragePath::NonUtf8)?;
        Self::new(value)
    }
}

impl TryFrom<PathBuf> for RelativeStoragePath {
    type Error = InvalidStoragePath;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(value.as_path())
    }
}

/// A single safe path component used by create and rename operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageFileName {
    value: String,
}

impl StorageFileName {
    pub fn new(value: impl AsRef<str>) -> Result<Self, InvalidStoragePath> {
        let components = parse_components(value.as_ref())?;
        if components.len() != 1 {
            return Err(InvalidStoragePath::MultipleComponents);
        }

        Ok(Self {
            value: components.into_iter().next().expect("one component"),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for StorageFileName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

fn parse_components(value: &str) -> Result<Vec<String>, InvalidStoragePath> {
    if value.is_empty() {
        return Err(InvalidStoragePath::Empty);
    }
    if value.contains('\0') {
        return Err(InvalidStoragePath::NulByte);
    }
    if value.starts_with(['/', '\\']) || has_windows_prefix(value) {
        return Err(InvalidStoragePath::Absolute);
    }

    value.split(['/', '\\']).map(validate_component).collect()
}

fn validate_component(component: &str) -> Result<String, InvalidStoragePath> {
    if component.is_empty() {
        return Err(InvalidStoragePath::EmptyComponent);
    }
    if matches!(component, "." | "..") {
        return Err(InvalidStoragePath::Traversal);
    }
    if component.ends_with([' ', '.']) {
        return Err(InvalidStoragePath::TrailingDotOrSpace);
    }
    if component.chars().any(|character| {
        character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
    }) {
        return Err(InvalidStoragePath::InvalidCharacter);
    }
    if is_reserved_windows_name(component) {
        return Err(InvalidStoragePath::ReservedName);
    }

    Ok(component.to_owned())
}

fn has_windows_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_reserved_windows_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();

    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || numbered_device(&stem, "COM")
        || numbered_device(&stem, "LPT")
}

fn numbered_device(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|number| matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidStoragePath {
    #[error("storage path must not be empty")]
    Empty,
    #[error("storage path must be relative")]
    Absolute,
    #[error("storage path must not contain traversal components")]
    Traversal,
    #[error("storage path must not contain empty components")]
    EmptyComponent,
    #[error("storage path must not contain NUL bytes")]
    NulByte,
    #[error("storage path contains a character unsupported by the storage policy")]
    InvalidCharacter,
    #[error("storage path components must not end in a dot or space")]
    TrailingDotOrSpace,
    #[error("storage path uses a reserved Windows device name")]
    ReservedName,
    #[error("storage path must be valid UTF-8")]
    NonUtf8,
    #[error("file name must contain exactly one path component")]
    MultipleComponents,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_both_separator_styles() {
        for input in [
            "scriptfiles/config/server.cfg",
            "scriptfiles\\config\\server.cfg",
        ] {
            let path = RelativeStoragePath::new(input).unwrap();
            assert_eq!(path.as_normalized_str(), "scriptfiles/config/server.cfg");
            assert_eq!(path.file_name(), Some("server.cfg"));
        }
    }

    #[test]
    fn models_root_join_and_parent_without_string_concatenation() {
        let root = RelativeStoragePath::root();
        let directory = RelativeStoragePath::new("scriptfiles/config").unwrap();
        let name = StorageFileName::new("server.cfg").unwrap();
        let file = directory.join(&name);

        assert!(root.is_root());
        assert_eq!(file.to_string(), "scriptfiles/config/server.cfg");
        assert_eq!(
            file.to_path_buf(),
            PathBuf::from("scriptfiles")
                .join("config")
                .join("server.cfg")
        );
        assert_eq!(file.parent(), Some(directory.clone()));
        assert_eq!(
            RelativeStoragePath::new("server.cfg").unwrap().parent(),
            Some(root)
        );

        let nested = RelativeStoragePath::new("nested/settings.cfg").unwrap();
        assert_eq!(
            directory.join_path(&nested).to_string(),
            "scriptfiles/config/nested/settings.cfg"
        );
    }

    #[test]
    fn checks_ancestor_relationship_by_component_and_ignores_ascii_case() {
        let ignored = RelativeStoragePath::new("ScriptFiles/Cache").unwrap();

        assert!(ignored.is_within_case_insensitive(&ignored));
        assert!(
            RelativeStoragePath::new("scriptfiles/cache/data.bin")
                .unwrap()
                .is_within_case_insensitive(&ignored)
        );
        assert!(
            !RelativeStoragePath::new("scriptfiles/cache-old/data.bin")
                .unwrap()
                .is_within_case_insensitive(&ignored)
        );
        assert!(
            !RelativeStoragePath::new("cache/data.bin")
                .unwrap()
                .is_within_case_insensitive(&ignored)
        );
    }

    #[test]
    fn rejects_absolute_traversal_and_ambiguous_paths() {
        for input in [
            "",
            "/etc/passwd",
            "\\\\server\\share",
            "C:\\server\\config",
            "../server.cfg",
            "config/../server.cfg",
            "config/./server.cfg",
            "config//server.cfg",
            "config/server.cfg/",
            "config/server.cfg:secret",
            "config/server.cfg ",
            "config/server.cfg.",
            "config/CON",
            "config/lpt1.txt",
            "config/*.cfg",
        ] {
            assert!(
                RelativeStoragePath::new(input).is_err(),
                "unsafe path was accepted: {input:?}"
            );
        }
    }

    #[test]
    fn file_name_rejects_paths_but_accepts_regular_names() {
        assert_eq!(
            StorageFileName::new("server.cfg").unwrap().as_str(),
            "server.cfg"
        );

        for input in ["", "../server.cfg", "config/server.cfg", "NUL.txt"] {
            assert!(StorageFileName::new(input).is_err());
        }
    }
}
