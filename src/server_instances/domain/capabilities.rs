use std::collections::BTreeSet;

/// Stable internal vocabulary behind the versioned capabilities exposed by
/// the presentation layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstanceCapability {
    Overview,
    Lifecycle,
    Configuration,
    Maps,
    Backups,
    Incidents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceCapabilities(BTreeSet<InstanceCapability>);

impl InstanceCapabilities {
    pub fn new(capabilities: impl IntoIterator<Item = InstanceCapability>) -> Self {
        Self(capabilities.into_iter().collect())
    }

    pub fn primary() -> Self {
        Self::new([
            InstanceCapability::Overview,
            InstanceCapability::Lifecycle,
            InstanceCapability::Configuration,
            InstanceCapability::Maps,
            InstanceCapability::Backups,
            InstanceCapability::Incidents,
        ])
    }

    pub fn contains(&self, capability: InstanceCapability) -> bool {
        self.0.contains(&capability)
    }

    pub fn iter(&self) -> impl Iterator<Item = InstanceCapability> + '_ {
        self.0.iter().copied()
    }
}

impl IntoIterator for InstanceCapabilities {
    type Item = InstanceCapability;
    type IntoIter = std::collections::btree_set::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
