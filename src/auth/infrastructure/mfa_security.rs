use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::auth::{
    application::mfa::ports::{
        MfaChallengeTokenGenerator, MfaChallengeTokenHasher, MfaClock, MfaSecurityError,
        MfaSecurityFuture, RecoveryCodeGenerator, RecoveryCodeHasher, TotpSecretCipher,
        TotpSecretGenerator, TotpVerifier,
    },
    domain::mfa::{
        EncryptedTotpSecret, MfaChallengeToken, MfaChallengeTokenHash, RecoveryCode,
        RecoveryCodeHash, TotpCode, TotpSecret,
    },
    domain::models::UserId,
};

const TOTP_SECRET_BYTES: usize = 20;
const CHALLENGE_TOKEN_BYTES: usize = 32;
const RECOVERY_CODE_BYTES: usize = 10;
const MAX_RECOVERY_CODES: usize = 64;
const AES_KEY_BYTES: usize = 32;
const AES_NONCE_BYTES: usize = 12;
const AES_TAG_BYTES: usize = 16;
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_AAD_PREFIX: &[u8] = b"lara.auth.totp-secret.v1";
const MIN_TOTP_PERIOD_SECONDS: u64 = 15;
const MAX_TOTP_PERIOD_SECONDS: u64 = 5 * 60;
const MAX_TOTP_CLOCK_SKEW_STEPS: u8 = 2;

#[derive(Debug, Clone, Copy, Default)]
pub struct OsTotpSecretGenerator;

impl TotpSecretGenerator for OsTotpSecretGenerator {
    fn generate(&self) -> Result<TotpSecret, MfaSecurityError> {
        let mut bytes = Zeroizing::new(vec![0_u8; TOTP_SECRET_BYTES]);
        OsRng
            .try_fill_bytes(bytes.as_mut_slice())
            .map_err(|_| MfaSecurityError::Generation)?;
        TotpSecret::new(bytes.to_vec()).map_err(|_| MfaSecurityError::Generation)
    }
}

pub struct Aes256GcmTotpSecretCipher {
    cipher: Aes256Gcm,
    key_version: u32,
}

impl Aes256GcmTotpSecretCipher {
    pub fn new(key: &[u8], key_version: u32) -> Result<Self, MfaSecurityConfigurationError> {
        if key.len() != AES_KEY_BYTES {
            return Err(MfaSecurityConfigurationError::EncryptionKeyLength);
        }
        if key_version == 0 {
            return Err(MfaSecurityConfigurationError::EncryptionKeyVersion);
        }
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| MfaSecurityConfigurationError::EncryptionKeyLength)?;
        Ok(Self {
            cipher,
            key_version,
        })
    }

    pub fn from_hex(key: &str, key_version: u32) -> Result<Self, MfaSecurityConfigurationError> {
        let decoded = Zeroizing::new(decode_hex_key(key)?);
        Self::new(decoded.as_slice(), key_version)
    }
}

impl TotpSecretCipher for Aes256GcmTotpSecretCipher {
    fn encrypt(
        &self,
        user_id: UserId,
        secret: &TotpSecret,
    ) -> Result<EncryptedTotpSecret, MfaSecurityError> {
        let mut nonce = [0_u8; AES_NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| MfaSecurityError::Generation)?;
        let ciphertext = self
            .cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: secret.as_bytes(),
                    aad: &envelope_aad(user_id),
                },
            )
            .map_err(|_| MfaSecurityError::Encryption)?;

        let mut envelope = Vec::with_capacity(1 + AES_NONCE_BYTES + ciphertext.len());
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        EncryptedTotpSecret::new(envelope).map_err(|_| MfaSecurityError::Encryption)
    }

    fn decrypt(
        &self,
        user_id: UserId,
        secret: &EncryptedTotpSecret,
    ) -> Result<TotpSecret, MfaSecurityError> {
        let envelope = secret.as_bytes();
        if envelope.len() < 1 + AES_NONCE_BYTES + AES_TAG_BYTES || envelope[0] != ENVELOPE_VERSION {
            return Err(MfaSecurityError::Decryption);
        }
        let (nonce, ciphertext) = envelope[1..].split_at(AES_NONCE_BYTES);
        let nonce =
            <[u8; AES_NONCE_BYTES]>::try_from(nonce).map_err(|_| MfaSecurityError::Decryption)?;
        let plaintext = Zeroizing::new(
            self.cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &envelope_aad(user_id),
                    },
                )
                .map_err(|_| MfaSecurityError::Decryption)?,
        );
        TotpSecret::new(plaintext.to_vec()).map_err(|_| MfaSecurityError::Decryption)
    }

    fn key_version(&self) -> u32 {
        self.key_version
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Rfc6238TotpVerifier {
    period_seconds: u64,
    digits: u32,
    allowed_clock_skew_steps: u8,
}

impl Rfc6238TotpVerifier {
    pub fn new(
        period_seconds: u64,
        digits: usize,
        allowed_clock_skew_steps: u8,
    ) -> Result<Self, MfaSecurityConfigurationError> {
        if !(MIN_TOTP_PERIOD_SECONDS..=MAX_TOTP_PERIOD_SECONDS).contains(&period_seconds) {
            return Err(MfaSecurityConfigurationError::TotpPeriod);
        }
        if !matches!(digits, 6 | 8) {
            return Err(MfaSecurityConfigurationError::TotpDigits);
        }
        if allowed_clock_skew_steps > MAX_TOTP_CLOCK_SKEW_STEPS {
            return Err(MfaSecurityConfigurationError::TotpClockSkew);
        }
        let digits =
            u32::try_from(digits).map_err(|_| MfaSecurityConfigurationError::TotpDigits)?;
        Ok(Self {
            period_seconds,
            digits,
            allowed_clock_skew_steps,
        })
    }

    fn code_for_step(&self, secret: &TotpSecret, step: u64) -> Result<String, MfaSecurityError> {
        type HmacSha1 = Hmac<Sha1>;

        let mut mac = <HmacSha1 as Mac>::new_from_slice(secret.as_bytes())
            .map_err(|_| MfaSecurityError::Totp)?;
        mac.update(&step.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let binary = (u32::from(digest[offset] & 0x7f) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]);
        let modulo = 10_u32
            .checked_pow(self.digits)
            .ok_or(MfaSecurityError::Totp)?;
        Ok(format!(
            "{:0width$}",
            binary % modulo,
            width = self.digits as usize
        ))
    }
}

impl TotpVerifier for Rfc6238TotpVerifier {
    fn verify(
        &self,
        secret: &TotpSecret,
        code: &TotpCode,
        now: DateTime<Utc>,
    ) -> Result<Option<u64>, MfaSecurityError> {
        if code.as_str().len() != self.digits as usize {
            return Ok(None);
        }
        let timestamp = u64::try_from(now.timestamp()).map_err(|_| MfaSecurityError::Totp)?;
        let current_step = timestamp / self.period_seconds;

        for offset in skew_offsets(self.allowed_clock_skew_steps) {
            let Some(step) = current_step.checked_add_signed(i64::from(offset)) else {
                continue;
            };
            let expected = self.code_for_step(secret, step)?;
            if bool::from(expected.as_bytes().ct_eq(code.as_str().as_bytes())) {
                return Ok(Some(step));
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OsMfaChallengeTokenGenerator;

impl MfaChallengeTokenGenerator for OsMfaChallengeTokenGenerator {
    fn generate(&self) -> Result<MfaChallengeToken, MfaSecurityError> {
        let mut bytes = Zeroizing::new([0_u8; CHALLENGE_TOKEN_BYTES]);
        OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| MfaSecurityError::Generation)?;
        MfaChallengeToken::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
            .map_err(|_| MfaSecurityError::Generation)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256MfaChallengeTokenHasher;

impl MfaChallengeTokenHasher for Sha256MfaChallengeTokenHasher {
    fn hash(&self, token: &MfaChallengeToken) -> MfaChallengeTokenHash {
        MfaChallengeTokenHash::new(Sha256::digest(token.as_str().as_bytes()).into())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OsRecoveryCodeGenerator;

impl RecoveryCodeGenerator for OsRecoveryCodeGenerator {
    fn generate(&self, count: usize) -> Result<Vec<RecoveryCode>, MfaSecurityError> {
        if count == 0 || count > MAX_RECOVERY_CODES {
            return Err(MfaSecurityError::Generation);
        }
        (0..count)
            .map(|_| {
                let mut bytes = Zeroizing::new([0_u8; RECOVERY_CODE_BYTES]);
                OsRng
                    .try_fill_bytes(bytes.as_mut())
                    .map_err(|_| MfaSecurityError::Generation)?;
                RecoveryCode::new(format_recovery_code(bytes.as_ref()))
                    .map_err(|_| MfaSecurityError::Generation)
            })
            .collect()
    }
}

#[derive(Clone, Default)]
pub struct Argon2RecoveryCodeHasher {
    argon2: Argon2<'static>,
}

impl RecoveryCodeHasher for Argon2RecoveryCodeHasher {
    fn hash<'a>(&'a self, code: &'a RecoveryCode) -> MfaSecurityFuture<'a, RecoveryCodeHash> {
        let argon2 = self.argon2.clone();
        let code = Zeroizing::new(code.as_str().to_owned());
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let salt = SaltString::generate(&mut OsRng);
                let hash = argon2
                    .hash_password(code.as_bytes(), &salt)
                    .map_err(|_| MfaSecurityError::RecoveryCodeHash)?
                    .to_string();
                RecoveryCodeHash::new(hash).map_err(|_| MfaSecurityError::RecoveryCodeHash)
            })
            .await
            .map_err(|_| MfaSecurityError::RecoveryCodeHash)?
        })
    }

    fn verify<'a>(
        &'a self,
        code: &'a RecoveryCode,
        hash: &'a RecoveryCodeHash,
    ) -> MfaSecurityFuture<'a, bool> {
        let argon2 = self.argon2.clone();
        let code = Zeroizing::new(code.as_str().to_owned());
        let hash = hash.as_str().to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let hash =
                    PasswordHash::new(&hash).map_err(|_| MfaSecurityError::RecoveryCodeHash)?;
                Ok(argon2.verify_password(code.as_bytes(), &hash).is_ok())
            })
            .await
            .map_err(|_| MfaSecurityError::RecoveryCodeHash)?
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemMfaClock;

impl MfaClock for SystemMfaClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum MfaSecurityConfigurationError {
    #[error("MFA encryption key must contain exactly 32 bytes")]
    EncryptionKeyLength,
    #[error("MFA encryption key must contain hexadecimal characters")]
    EncryptionKeyEncoding,
    #[error("MFA encryption key version must be positive")]
    EncryptionKeyVersion,
    #[error("TOTP period must be positive")]
    TotpPeriod,
    #[error("TOTP must use either 6 or 8 digits")]
    TotpDigits,
    #[error("TOTP clock skew must not exceed two time steps")]
    TotpClockSkew,
}

fn envelope_aad(user_id: UserId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_PREFIX.len() + size_of::<i64>());
    aad.extend_from_slice(ENVELOPE_AAD_PREFIX);
    aad.extend_from_slice(&user_id.get().to_be_bytes());
    aad
}

fn decode_hex_key(value: &str) -> Result<Vec<u8>, MfaSecurityConfigurationError> {
    if value.len() != AES_KEY_BYTES * 2 {
        return Err(MfaSecurityConfigurationError::EncryptionKeyLength);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, MfaSecurityConfigurationError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(MfaSecurityConfigurationError::EncryptionKeyEncoding),
    }
}

fn skew_offsets(skew: u8) -> impl Iterator<Item = i8> {
    let skew = skew as i8;
    std::iter::once(0).chain((1..=skew).flat_map(|offset| [-offset, offset]))
}

fn format_recovery_code(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2 + (bytes.len() * 2 / 4));
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && index % 2 == 0 {
            result.push('-');
        }
        use std::fmt::Write;
        write!(result, "{byte:02X}").expect("writing to String is infallible");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_rfc_6238_sha1_vectors() {
        let verifier = Rfc6238TotpVerifier::new(30, 8, 0).unwrap();
        let secret = TotpSecret::new(b"12345678901234567890".to_vec()).unwrap();
        for (timestamp, expected) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            let now = DateTime::from_timestamp(timestamp, 0).unwrap();
            let code = TotpCode::new(expected).unwrap();
            assert_eq!(
                verifier.verify(&secret, &code, now).unwrap(),
                Some(timestamp as u64 / 30)
            );
        }
    }

    #[test]
    fn accepts_only_the_configured_clock_skew_and_digits() {
        let strict = Rfc6238TotpVerifier::new(30, 6, 0).unwrap();
        let tolerant = Rfc6238TotpVerifier::new(30, 6, 1).unwrap();
        let secret = TotpSecret::new(b"12345678901234567890".to_vec()).unwrap();
        let previous = strict.code_for_step(&secret, 99).unwrap();
        let previous = TotpCode::new(previous).unwrap();
        let now = DateTime::from_timestamp(3_000, 0).unwrap();

        assert_eq!(strict.verify(&secret, &previous, now).unwrap(), None);
        assert_eq!(tolerant.verify(&secret, &previous, now).unwrap(), Some(99));
        assert_eq!(
            tolerant
                .verify(&secret, &TotpCode::new("12345678").unwrap(), now)
                .unwrap(),
            None
        );

        assert!(matches!(
            Rfc6238TotpVerifier::new(14, 6, 1),
            Err(MfaSecurityConfigurationError::TotpPeriod)
        ));
        assert!(matches!(
            Rfc6238TotpVerifier::new(30, 7, 1),
            Err(MfaSecurityConfigurationError::TotpDigits)
        ));
        assert!(matches!(
            Rfc6238TotpVerifier::new(30, 6, 3),
            Err(MfaSecurityConfigurationError::TotpClockSkew)
        ));
    }

    #[test]
    fn encrypts_with_random_nonce_and_rejects_tampering() {
        let cipher = Aes256GcmTotpSecretCipher::new(&[7; AES_KEY_BYTES], 1).unwrap();
        let secret = TotpSecret::new(b"top-secret-seed".to_vec()).unwrap();
        let user_id = UserId::new(42).unwrap();
        let first = cipher.encrypt(user_id, &secret).unwrap();
        let second = cipher.encrypt(user_id, &secret).unwrap();

        assert_ne!(first, second);
        assert_eq!(cipher.decrypt(user_id, &first).unwrap(), secret);
        assert_eq!(
            cipher.decrypt(UserId::new(7).unwrap(), &first),
            Err(MfaSecurityError::Decryption)
        );
        assert_eq!(cipher.key_version(), 1);

        let mut corrupted = first.into_bytes();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        let corrupted = EncryptedTotpSecret::new(corrupted).unwrap();
        assert_eq!(
            cipher.decrypt(user_id, &corrupted),
            Err(MfaSecurityError::Decryption)
        );
    }

    #[test]
    fn validates_hex_key_and_envelope_version() {
        assert!(Aes256GcmTotpSecretCipher::from_hex(&"11".repeat(32), 1).is_ok());
        assert!(matches!(
            Aes256GcmTotpSecretCipher::from_hex(&"11".repeat(31), 1),
            Err(MfaSecurityConfigurationError::EncryptionKeyLength)
        ));
        assert!(matches!(
            Aes256GcmTotpSecretCipher::from_hex(&format!("{}zz", "11".repeat(31)), 1),
            Err(MfaSecurityConfigurationError::EncryptionKeyEncoding)
        ));
    }

    #[test]
    fn challenge_tokens_are_random_url_safe_and_deterministically_hashed() {
        let generator = OsMfaChallengeTokenGenerator;
        let first = generator.generate().unwrap();
        let second = generator.generate().unwrap();
        let hasher = Sha256MfaChallengeTokenHasher;

        assert_ne!(first, second);
        assert!(!first.as_str().contains(['+', '/', '=']));
        assert_eq!(hasher.hash(&first), hasher.hash(&first));
        assert_ne!(hasher.hash(&first), hasher.hash(&second));
    }

    #[tokio::test]
    async fn recovery_codes_are_unique_and_argon2_hashed() {
        let codes = OsRecoveryCodeGenerator.generate(10).unwrap();
        let hasher = Argon2RecoveryCodeHasher::default();
        let hash = hasher.hash(&codes[0]).await.unwrap();
        let unique = codes
            .iter()
            .map(|code| code.as_str())
            .collect::<std::collections::HashSet<_>>();

        assert_eq!(codes.len(), 10);
        assert_eq!(unique.len(), codes.len());
        assert!(codes.iter().all(|code| code.as_str().len() == 24));
        assert!(hasher.verify(&codes[0], &hash).await.unwrap());
        assert!(!hasher.verify(&codes[1], &hash).await.unwrap());
        assert_ne!(hash.as_str(), codes[0].as_str());
    }
}
