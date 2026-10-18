mod dto;
pub mod extractors;
mod handlers;
mod mfa_handlers;
mod openapi;
mod routes;
pub mod state;

pub use openapi::{base_document as openapi_document, router as openapi_router};
pub use routes::mfa_router;
#[cfg(test)]
pub use routes::router;

#[cfg(test)]
mod tests;
