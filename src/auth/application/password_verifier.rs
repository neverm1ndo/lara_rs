pub trait PasswordVerifier: Send + Sync {
    fn verify(&self, password: &str, stored_hash: &str) -> bool;
}
