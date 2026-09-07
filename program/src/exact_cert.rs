//! Tier-1 exact certificate verifier (Goal A) — NOT full coqchk.
//!
//! Fail-closed: empty cert, unknown version, PLACEHOLDER flag, hash mismatch,
//! or id/visible mismatch ⇒ Error. Never treat NotImplemented / placeholder as Valid.

use sha2::{Digest, Sha256};

/// `"T1CERT0\0"`
pub const MAGIC: [u8; 8] = *b"T1CERT0\0";
pub const VERSION: u32 = 0;
/// Bit0: placeholder / NotImplemented stub — must be unset for acceptance.
pub const FLAG_PLACEHOLDER: u32 = 1;
pub const CERT_LEN: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier1Cert {
    pub version: u32,
    pub flags: u32,
    pub job_id: [u8; 32],
    pub question_sha256: [u8; 32],
    pub answer_sha256: [u8; 32],
    pub visible: u32,
    pub nat_expr_eval: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    Empty,
    BadLength,
    BadMagic,
    BadVersion,
    PlaceholderFlag,
    IdMismatch,
    VisibleMismatch,
    EvalMismatch,
    QuestionHashMismatch,
    AnswerHashMismatch,
}

impl CertError {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertError::Empty => "tier1-cert: empty (fail-closed)",
            CertError::BadLength => "tier1-cert: bad length",
            CertError::BadMagic => "tier1-cert: bad magic",
            CertError::BadVersion => "tier1-cert: unknown version",
            CertError::PlaceholderFlag => {
                "tier1-cert: PLACEHOLDER/NotImplemented flag set (fail-closed)"
            }
            CertError::IdMismatch => "tier1-cert: job_id ≠ stdin id",
            CertError::VisibleMismatch => "tier1-cert: visible ≠ stdin visible",
            CertError::EvalMismatch => "tier1-cert: nat_expr_eval ≠ visible",
            CertError::QuestionHashMismatch => "tier1-cert: question sha256 mismatch",
            CertError::AnswerHashMismatch => "tier1-cert: answer sha256 mismatch",
        }
    }
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn put_u32_le(out: &mut [u8], v: u32) {
    out.copy_from_slice(&v.to_le_bytes());
}

/// SHA-256 of bytes (guest + host must match).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

pub fn encode(cert: &Tier1Cert) -> [u8; CERT_LEN] {
    let mut out = [0u8; CERT_LEN];
    out[0..8].copy_from_slice(&MAGIC);
    put_u32_le(&mut out[8..12], cert.version);
    put_u32_le(&mut out[12..16], cert.flags);
    out[16..48].copy_from_slice(&cert.job_id);
    out[48..80].copy_from_slice(&cert.question_sha256);
    out[80..112].copy_from_slice(&cert.answer_sha256);
    put_u32_le(&mut out[112..116], cert.visible);
    put_u32_le(&mut out[116..120], cert.nat_expr_eval);
    out
}

pub fn decode(bytes: &[u8]) -> Result<Tier1Cert, CertError> {
    if bytes.is_empty() {
        return Err(CertError::Empty);
    }
    if bytes.len() != CERT_LEN {
        return Err(CertError::BadLength);
    }
    if bytes[0..8] != MAGIC {
        return Err(CertError::BadMagic);
    }
    let version = u32_le(&bytes[8..12]);
    if version != VERSION {
        return Err(CertError::BadVersion);
    }
    let flags = u32_le(&bytes[12..16]);
    if flags & FLAG_PLACEHOLDER != 0 {
        return Err(CertError::PlaceholderFlag);
    }
    let mut job_id = [0u8; 32];
    job_id.copy_from_slice(&bytes[16..48]);
    let mut question_sha256 = [0u8; 32];
    question_sha256.copy_from_slice(&bytes[48..80]);
    let mut answer_sha256 = [0u8; 32];
    answer_sha256.copy_from_slice(&bytes[80..112]);
    let visible = u32_le(&bytes[112..116]);
    let nat_expr_eval = u32_le(&bytes[116..120]);
    Ok(Tier1Cert {
        version,
        flags,
        job_id,
        question_sha256,
        answer_sha256,
        visible,
        nat_expr_eval,
    })
}

/// Build a Tier-1 cert from job bytes (host / tests).
pub fn build(
    job_id: [u8; 32],
    question: &[u8],
    answer: &[u8],
    visible: u32,
    nat_expr_eval: u32,
) -> Tier1Cert {
    Tier1Cert {
        version: VERSION,
        flags: 0,
        job_id,
        question_sha256: sha256(question),
        answer_sha256: sha256(answer),
        visible,
        nat_expr_eval,
    }
}

/// Verify cert against stdin bindings. Fail-closed on any mismatch.
pub fn verify_against_inputs(
    cert_bytes: &[u8],
    id: &[u8; 32],
    visible: u32,
    question: &[u8],
    answer: &[u8],
) -> Result<Tier1Cert, CertError> {
    let cert = decode(cert_bytes)?;
    if &cert.job_id != id {
        return Err(CertError::IdMismatch);
    }
    if cert.visible != visible {
        return Err(CertError::VisibleMismatch);
    }
    if cert.nat_expr_eval != cert.visible {
        return Err(CertError::EvalMismatch);
    }
    if cert.question_sha256 != sha256(question) {
        return Err(CertError::QuestionHashMismatch);
    }
    if cert.answer_sha256 != sha256(answer) {
        return Err(CertError::AnswerHashMismatch);
    }
    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_verify_ok() {
        let id = [7u8; 32];
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition answer : Target := ex_intro _ 2 eq_refl.\nDefinition visible_result : nat := 2.\n";
        let cert = build(id, q, a, 2, 2);
        let bytes = encode(&cert);
        assert_eq!(bytes.len(), CERT_LEN);
        verify_against_inputs(&bytes, &id, 2, q, a).unwrap();
    }

    #[test]
    fn empty_fail_closed() {
        let id = [0u8; 32];
        assert_eq!(
            verify_against_inputs(&[], &id, 0, b"q", b"a").unwrap_err(),
            CertError::Empty
        );
    }

    #[test]
    fn placeholder_flag_fail_closed() {
        let id = [1u8; 32];
        let mut cert = build(id, b"q", b"a", 1, 1);
        cert.flags |= FLAG_PLACEHOLDER;
        let bytes = encode(&cert);
        assert_eq!(
            verify_against_inputs(&bytes, &id, 1, b"q", b"a").unwrap_err(),
            CertError::PlaceholderFlag
        );
    }

    #[test]
    fn hash_mismatch_fail_closed() {
        let id = [2u8; 32];
        let cert = build(id, b"q1", b"a", 1, 1);
        let bytes = encode(&cert);
        assert_eq!(
            verify_against_inputs(&bytes, &id, 1, b"q2", b"a").unwrap_err(),
            CertError::QuestionHashMismatch
        );
    }
}
