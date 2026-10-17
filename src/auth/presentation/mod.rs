mod dto;
pub mod extractors;
mod handlers;
#[allow(dead_code)]
mod mfa_handlers;
mod openapi;
mod routes;
pub mod state;

pub use openapi::{base_document as openapi_document, router as openapi_router};
pub use routes::router;

#[cfg(test)]
mod tests;
