use std::{convert::Infallible, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    auth::presentation::extractors::JwtExtractorState, user::application::get_user::GetUser,
};

pub trait UserState: JwtExtractorState {
    fn get_user_service(&self) -> Arc<dyn GetUser>;
}

pub struct UserServiceHandle(pub Arc<dyn GetUser>);

impl<S> FromRequestParts<S> for UserServiceHandle
where
    S: UserState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(state.get_user_service()))
    }
}
