mod access;
mod events;
mod file_policy;

// These form the public domain surface and will be consumed by the application
// layer introduced in the next step.
#[allow(unused_imports)]
pub use access::{ConfigurationAccess, ConfigurationAccessError, ConfigurationAccessLevel};
#[allow(unused_imports)]
pub use events::{
    CONFIGURATION_FILE_CHANGED_EVENT_TYPE, ConfigurationDomainEvent, ConfigurationEventId,
    ConfigurationFileChange, ConfigurationFileChanged, InvalidConfigurationDomainEvent,
};
#[allow(unused_imports)]
pub use file_policy::{
    BinaryExtension, ConfigurationFileKind, ConfigurationFilePolicy, InvalidConfigurationFilePolicy,
};
