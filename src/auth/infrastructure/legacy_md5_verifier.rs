use md5::{Digest, Md5};
use subtle::ConstantTimeEq;

use crate::auth::application::password_verifier::PasswordVerifier;

const PWD_OFFSET: usize = 32;

pub struct LegacyMd5Verifier;

impl PasswordVerifier for LegacyMd5Verifier {
    /**
     * Верификация хэшированного пароля
     */
    fn verify(&self, password: &str, stored_hash: &str) -> bool {
        if password.is_empty() || !stored_hash.is_ascii() || stored_hash.len() <= PWD_OFFSET {
            return false;
        }

        let split_at = stored_hash.len() - PWD_OFFSET;
        let (salt, real_password) = stored_hash.split_at(split_at);

        let mut hasher = Md5::new();
        hasher.update(salt.as_bytes());
        hasher.update(password.as_bytes());

        let calculated = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        calculated.as_bytes().ct_eq(real_password.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_hash(salt: &str, password: &str) -> String {
        let digest = Md5::digest(format!("{salt}{password}").as_bytes());
        let digest = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("{salt}{digest}")
    }

    #[test]
    fn verifies_legacy_salted_md5_password() {
        let hash = legacy_hash("random-salt", "correct horse battery staple");

        assert!(LegacyMd5Verifier.verify("correct horse battery staple", &hash));
        assert!(!LegacyMd5Verifier.verify("wrong password", &hash));
    }

    #[test]
    fn rejects_empty_password_and_malformed_hashes() {
        assert!(!LegacyMd5Verifier.verify("", &legacy_hash("salt", "password")));
        assert!(!LegacyMd5Verifier.verify("password", "short"));
        assert!(!LegacyMd5Verifier.verify("password", "соль00000000000000000000000000000000"));
    }
}
