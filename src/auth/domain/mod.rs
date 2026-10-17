// The MFA domain is introduced before its application and infrastructure
// adapters; remove this staged-integration allowance once those ports use all
// of the model's public API.
#[allow(dead_code)]
pub mod mfa;
pub mod models;
pub mod rules;
