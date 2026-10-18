mod dto;
mod handlers;
pub mod openapi;
mod routes;
pub mod state;

pub use openapi::base_document as openapi_document;
pub use routes::router;

#[cfg(test)]
mod tests;
