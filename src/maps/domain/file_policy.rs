use std::{collections::HashSet, fmt};

use thiserror::Error;

use crate::shared::file_storage::path::RelativeStoragePath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapFileKind {
    Active,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MapFilePath {
    path: RelativeStoragePath,
    kind: MapFileKind,
}

impl MapFilePath {
    pub fn new(path: RelativeStoragePath) -> Result<Self, InvalidMapFilePath> {
        let file_name = path.file_name().ok_or(InvalidMapFilePath::Root)?;
        let normalized = file_name.to_ascii_lowercase();
        let (stem, kind) = if let Some(stem) = normalized.strip_suffix(".map.off") {
            (stem, MapFileKind::Disabled)
        } else if let Some(stem) = normalized.strip_suffix(".map") {
            (stem, MapFileKind::Active)
        } else {
            return Err(InvalidMapFilePath::UnsupportedExtension);
        };

        if stem.is_empty() {
            return Err(InvalidMapFilePath::EmptyName);
        }

        Ok(Self { path, kind })
    }

    pub fn as_storage_path(&self) -> &RelativeStoragePath {
        &self.path
    }

    pub fn into_storage_path(self) -> RelativeStoragePath {
        self.path
    }

    pub fn kind(&self) -> MapFileKind {
        self.kind
    }

    pub fn file_name(&self) -> &str {
        self.path
            .file_name()
            .expect("validated map path is never the capability root")
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.path
            .as_normalized_str()
            .eq_ignore_ascii_case(&other.path.as_normalized_str())
    }
}

impl TryFrom<RelativeStoragePath> for MapFilePath {
    type Error = InvalidMapFilePath;

    fn try_from(path: RelativeStoragePath) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl fmt::Display for MapFilePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.path.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MapFilePolicy;

impl MapFilePolicy {
    pub fn recognize(self, path: &RelativeStoragePath) -> Result<MapFilePath, InvalidMapFilePath> {
        MapFilePath::new(path.clone())
    }

    pub fn recognizes(self, path: &RelativeStoragePath) -> bool {
        self.recognize(path).is_ok()
    }

    pub fn ensure_unique<'a>(
        self,
        paths: impl IntoIterator<Item = &'a MapFilePath>,
    ) -> Result<(), InvalidMapFilePath> {
        let mut unique = HashSet::new();
        for path in paths {
            if !unique.insert(
                path.as_storage_path()
                    .as_normalized_str()
                    .to_ascii_lowercase(),
            ) {
                return Err(InvalidMapFilePath::DuplicatePath);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidMapFilePath {
    #[error("the maps capability root is not a map file")]
    Root,
    #[error("map file names must end in .map or .map.off")]
    UnsupportedExtension,
    #[error("map file name must contain a non-empty stem")]
    EmptyName,
    #[error("map paths in one operation must be unique ignoring ASCII case")]
    DuplicatePath,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RelativeStoragePath {
        RelativeStoragePath::new(value).unwrap()
    }

    #[test]
    fn recognizes_active_and_disabled_maps_at_any_depth() {
        let cases = [
            ("race.map", MapFileKind::Active),
            ("city/race.MAP", MapFileKind::Active),
            ("interiors/shops/shop.map.off", MapFileKind::Disabled),
            ("archive/RACE.MAP.OFF", MapFileKind::Disabled),
        ];

        for (value, expected) in cases {
            let map = MapFilePath::new(path(value)).unwrap();
            assert_eq!(map.kind(), expected);
            assert_eq!(map.to_string(), value);
        }
    }

    #[test]
    fn rejects_root_empty_names_and_unrelated_files() {
        assert_eq!(
            MapFilePath::new(RelativeStoragePath::root()),
            Err(InvalidMapFilePath::Root)
        );
        for value in [".map", ".map.off"] {
            assert_eq!(
                MapFilePath::new(path(value)),
                Err(InvalidMapFilePath::EmptyName)
            );
        }
        for value in ["race.xml", "race.map.bak", "maps/race.pwn"] {
            assert_eq!(
                MapFilePath::new(path(value)),
                Err(InvalidMapFilePath::UnsupportedExtension)
            );
        }
    }

    #[test]
    fn detects_case_insensitive_duplicates_in_a_batch() {
        let first = MapFilePath::new(path("city/Race.map")).unwrap();
        let duplicate = MapFilePath::new(path("CITY/race.MAP")).unwrap();
        let other = MapFilePath::new(path("city/race.map.off")).unwrap();
        let policy = MapFilePolicy;

        assert!(first.conflicts_with(&duplicate));
        assert!(!first.conflicts_with(&other));
        assert_eq!(
            policy.ensure_unique([&first, &duplicate]),
            Err(InvalidMapFilePath::DuplicatePath)
        );
        policy.ensure_unique([&first, &other]).unwrap();
    }
}
