//! Acceptance kernel fragment + Tier-1/Tier-2 exact certificates for the BECOME Target shape.
//!
//! **Not** full `coqchk` / Rocq kernel (OCaml Coq cannot run inside SP1 today).
//! Tier-2 (WP3): guest verifies T2CERT0 + pinned checker_pin + safe_ok_digest + Nat fragment.
//! Host SafeChecker / coqchk are offline dual-path — not settlement TCB alone.

pub mod acceptance;
pub mod exact_cert;
pub mod exact_cert_t2;
pub mod nat_expr;
pub mod parse;

pub use acceptance::{
    check_development, check_with_tier1_cert, check_with_tier2_cert, AcceptanceBackend,
    AcceptanceError, CheckReport, CoqchkPortable, NatTargetFragment,
};
pub use exact_cert::{
    build as build_tier1_cert, encode as encode_tier1_cert, verify_against_inputs as verify_tier1_cert,
    CertError, Tier1Cert, CERT_LEN, FLAG_PLACEHOLDER, MAGIC, VERSION,
};
pub use exact_cert_t2::{
    encode as encode_tier2_cert, verify_against_inputs as verify_tier2_cert, Tier2Cert,
    CERT_LEN as T2_CERT_LEN, EXPECTED_CHECKER_PIN, MAGIC as T2_MAGIC,
};
