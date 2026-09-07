//! Tier-2 exact certificate verifier (T2CERT0) — NOT full coqchk / SafeChecker in-guest.
//!
//! Guest checks layout + binds + pinned checker_pin + recomputed safe_ok_digest
//! (ok_lines supplied on stdin). Fail-closed. Soundness of digest ⇒ SafeCheck Ok is theorem T2.

use sha2::{Digest, Sha256};

/// `"T2CERT0\0"`
pub const MAGIC: [u8; 8] = *b"T2CERT0\0";
pub const VERSION: u32 = 0;
pub const FLAG_PLACEHOLDER: u32 = 1;
pub const CERT_LEN: usize = 188;
pub const FRAGMENT_EXISTS: u32 = 0;
pub const FRAGMENT_EQ: u32 = 1;

/// Pinned `checker_pin` from formal/tier2/METAROCQ-PIN.json (packages canonical JSON).
/// Update when MetaRocq pin changes (new ELF / programVKey).
pub const EXPECTED_CHECKER_PIN: [u8; 32] = [
    0x18, 0xd2, 0x62, 0x0a, 0xfe, 0xbe, 0x95, 0xf3, 0xc1, 0x53, 0x53, 0x3f, 0x2d, 0xa6, 0x46,
    0x71, 0x40, 0x4e, 0x94, 0x19, 0xf3, 0x9e, 0x64, 0xd4, 0xdb, 0x01, 0x77, 0x79, 0x2d, 0x50,
    0xb0, 0x7f,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier2Cert {
    pub version: u32,
    pub flags: u32,
    pub job_id: [u8; 32],
    pub question_sha256: [u8; 32],
    pub answer_sha256: [u8; 32],
    pub visible: u32,
    pub nat_expr_eval: u32,
    pub fragment_kind: u32,
    pub checker_pin: [u8; 32],
    pub safe_ok_digest: [u8; 32],
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
    FragmentKind,
    CheckerPinMismatch,
    SafeOkDigestMismatch,
    EmptyOkLines,
}

impl CertError {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertError::Empty => "tier2-cert: empty (fail-closed)",
            CertError::BadLength => "tier2-cert: bad length",
            CertError::BadMagic => "tier2-cert: bad magic",
            CertError::BadVersion => "tier2-cert: unknown version",
            CertError::PlaceholderFlag => "tier2-cert: PLACEHOLDER flag set (fail-closed)",
            CertError::IdMismatch => "tier2-cert: job_id ≠ stdin id",
            CertError::VisibleMismatch => "tier2-cert: visible ≠ stdin visible",
            CertError::EvalMismatch => "tier2-cert: nat_expr_eval ≠ visible",
            CertError::QuestionHashMismatch => "tier2-cert: question sha256 mismatch",
            CertError::AnswerHashMismatch => "tier2-cert: answer sha256 mismatch",
            CertError::FragmentKind => "tier2-cert: fragment_kind not in WP0 domain",
            CertError::CheckerPinMismatch => "tier2-cert: checker_pin ≠ pinned P_mr",
            CertError::SafeOkDigestMismatch => "tier2-cert: safe_ok_digest mismatch",
            CertError::EmptyOkLines => "tier2-cert: empty ok_lines (fail-closed)",
        }
    }
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn put_u32_le(out: &mut [u8], v: u32) {
    out.copy_from_slice(&v.to_le_bytes());
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Recompute safe_ok_digest. `ok_lines_raw` must be the **canonical** host blob:
/// UTF-8 `join("\n", sorted(ok_lines)) + "\n"` (same as docs/TIER2-CERTIFICATE.md).
pub fn compute_safe_ok_digest(
    checker_pin: &[u8; 32],
    question_sha256: &[u8; 32],
    answer_sha256: &[u8; 32],
    visible: u32,
    ok_lines_raw: &[u8],
) -> Result<[u8; 32], CertError> {
    if ok_lines_raw.is_empty() {
        return Err(CertError::EmptyOkLines);
    }
    let mut h = Sha256::new();
    h.update(b"T2SAFEOK\0");
    h.update(checker_pin);
    h.update(question_sha256);
    h.update(answer_sha256);
    h.update(visible.to_le_bytes());
    h.update(ok_lines_raw);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    Ok(out)
}

pub fn encode(cert: &Tier2Cert) -> [u8; CERT_LEN] {
    let mut out = [0u8; CERT_LEN];
    out[0..8].copy_from_slice(&MAGIC);
    put_u32_le(&mut out[8..12], cert.version);
    put_u32_le(&mut out[12..16], cert.flags);
    out[16..48].copy_from_slice(&cert.job_id);
    out[48..80].copy_from_slice(&cert.question_sha256);
    out[80..112].copy_from_slice(&cert.answer_sha256);
    put_u32_le(&mut out[112..116], cert.visible);
    put_u32_le(&mut out[116..120], cert.nat_expr_eval);
    put_u32_le(&mut out[120..124], cert.fragment_kind);
    out[124..156].copy_from_slice(&cert.checker_pin);
    out[156..188].copy_from_slice(&cert.safe_ok_digest);
    out
}

pub fn decode(bytes: &[u8]) -> Result<Tier2Cert, CertError> {
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
    let fragment_kind = u32_le(&bytes[120..124]);
    if fragment_kind != FRAGMENT_EXISTS && fragment_kind != FRAGMENT_EQ {
        return Err(CertError::FragmentKind);
    }
    let mut checker_pin = [0u8; 32];
    checker_pin.copy_from_slice(&bytes[124..156]);
    let mut safe_ok_digest = [0u8; 32];
    safe_ok_digest.copy_from_slice(&bytes[156..188]);
    Ok(Tier2Cert {
        version,
        flags,
        job_id,
        question_sha256,
        answer_sha256,
        visible,
        nat_expr_eval,
        fragment_kind,
        checker_pin,
        safe_ok_digest,
    })
}

/// Verify cert against stdin bindings + ok_lines; enforce pinned checker_pin.
pub fn verify_against_inputs(
    cert_bytes: &[u8],
    id: &[u8; 32],
    visible: u32,
    question: &[u8],
    answer: &[u8],
    ok_lines_raw: &[u8],
) -> Result<Tier2Cert, CertError> {
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
    let qh = sha256(question);
    let ah = sha256(answer);
    if cert.question_sha256 != qh {
        return Err(CertError::QuestionHashMismatch);
    }
    if cert.answer_sha256 != ah {
        return Err(CertError::AnswerHashMismatch);
    }
    if cert.checker_pin != EXPECTED_CHECKER_PIN {
        return Err(CertError::CheckerPinMismatch);
    }
    let sod = compute_safe_ok_digest(
        &cert.checker_pin,
        &cert.question_sha256,
        &cert.answer_sha256,
        cert.visible,
        ok_lines_raw,
    )?;
    if sod != cert.safe_ok_digest {
        return Err(CertError::SafeOkDigestMismatch);
    }
    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ok_lines() -> Vec<u8> {
        // Must match host sorted join for digest tests — use fixed lines
        let lines = [
            "Environment is well-formed and Const(Question.Target,[]) has type: Sort(Prop)",
            "Environment is well-formed and Const(answer.answer,[]) has type: Const(Question.Target,[])",
            "Environment is well-formed and Const(answer.visible_result,[]) has type: Ind(Corelib.Init.Datatypes.nat,0,[])",
        ];
        let mut v = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            if i > 0 {
                v.push(b'\n');
            }
            v.extend_from_slice(l.as_bytes());
        }
        v.push(b'\n');
        v
    }

    fn make_cert(q: &[u8], a: &[u8], visible: u32, ok: &[u8]) -> ([u8; CERT_LEN], [u8; 32]) {
        let id = sha256(q);
        let qh = sha256(q);
        let ah = sha256(a);
        let sod = compute_safe_ok_digest(&EXPECTED_CHECKER_PIN, &qh, &ah, visible, ok).unwrap();
        let cert = Tier2Cert {
            version: VERSION,
            flags: 0,
            job_id: id,
            question_sha256: qh,
            answer_sha256: ah,
            visible,
            nat_expr_eval: visible,
            fragment_kind: FRAGMENT_EXISTS,
            checker_pin: EXPECTED_CHECKER_PIN,
            safe_ok_digest: sod,
        };
        (encode(&cert), id)
    }

    #[test]
    fn roundtrip_ok() {
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.\n";
        let a = b"Definition answer : Target := ex_intro _ 2 eq_refl.\nDefinition visible_result : nat := 2.\n";
        let ok = sample_ok_lines();
        let (bytes, id) = make_cert(q, a, 2, &ok);
        assert_eq!(bytes.len(), CERT_LEN);
        verify_against_inputs(&bytes, &id, 2, q, a, &ok).unwrap();
    }

    #[test]
    fn empty_fail_closed() {
        let id = [0u8; 32];
        assert_eq!(
            verify_against_inputs(&[], &id, 0, b"q", b"a", b"line\n").unwrap_err(),
            CertError::Empty
        );
    }

    #[test]
    fn placeholder_fail_closed() {
        let q = b"q";
        let a = b"a";
        let ok = sample_ok_lines();
        let (mut bytes, id) = make_cert(q, a, 1, &ok);
        // set PLACEHOLDER flag
        bytes[12] = 1;
        assert_eq!(
            verify_against_inputs(&bytes, &id, 1, q, a, &ok).unwrap_err(),
            CertError::PlaceholderFlag
        );
    }

    #[test]
    fn wrong_ok_lines_fail() {
        let q = b"q";
        let a = b"a";
        let ok = sample_ok_lines();
        let (bytes, id) = make_cert(q, a, 1, &ok);
        assert_eq!(
            verify_against_inputs(&bytes, &id, 1, q, a, b"tampered\n").unwrap_err(),
            CertError::SafeOkDigestMismatch
        );
    }
}
