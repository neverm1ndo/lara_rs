pub mod exception;
pub mod profile;
pub mod repositories;

// Public user-domain contract consumed by application and presentation layers
// in the following implementation steps.
#[allow(unused_imports)]
pub use profile::{UserId, UserProfile};
