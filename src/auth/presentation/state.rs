use std::{convert::Infallible, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::auth::application::login::Login;

pub trait LoginState: Send + Sync {
    fn login_service(&self) -> Arc<dyn Login>;
}

pub struct LoginServiceHandle(pub Arc<dyn Login>);

impl<S> FromRequestParts<S> for LoginServiceHandle
where
    S: LoginState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(state.login_service()))
    }
}
