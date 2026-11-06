pub mod authorization;
mod dto;
mod handlers;
pub mod openapi;
mod routes;
pub mod state;

#[allow(unused_imports)]
pub use openapi::base_document as openapi_document;
#[allow(unused_imports)]
pub use routes::router;

pub mod instance_routes;
pub mod instance_state;
#[cfg(test)]
mod instance_tests;
pub mod realtime;
#[cfg(test)]
mod tests;
