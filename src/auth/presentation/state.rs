use std::{convert::Infallible, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::auth::application::{
    login::Login,
    mfa::{login::MfaLogin, management::ManageMfa},
};

#[allow(dead_code)]
pub trait LoginState: Send + Sync {
    fn login_service(&self) -> Arc<dyn Login>;
}

#[allow(dead_code)]
pub struct LoginServiceHandle(pub Arc<dyn Login>);

pub trait MfaState: Send + Sync {
    fn mfa_login_service(&self) -> Arc<dyn MfaLogin>;
    fn mfa_management_service(&self) -> Arc<dyn ManageMfa>;
}

pub struct MfaLoginServiceHandle(pub Arc<dyn MfaLogin>);
pub struct MfaManagementServiceHandle(pub Arc<dyn ManageMfa>);

impl<S> FromRequestParts<S> for LoginServiceHandle
where
    S: LoginState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(state.login_service()))
    }
}

impl<S> FromRequestParts<S> for MfaLoginServiceHandle
where
    S: MfaState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(state.mfa_login_service()))
    }
}

impl<S> FromRequestParts<S> for MfaManagementServiceHandle
where
    S: MfaState,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(state.mfa_management_service()))
    }
}
