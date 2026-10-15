pub mod config;
// The storage foundation is intentionally introduced before its first domain
// adapter. Remove this allowance once the configuration context is wired in.
#[allow(dead_code)]
pub mod file_storage;
pub mod user_role;
