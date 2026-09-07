//! Acceptance kernel fragment + Tier-1 exact certificate for the BECOME Target shape.
//!
//! **Not** full `coqchk` / Rocq kernel (OCaml Coq cannot run inside SP1 today).
//! Tier-1 (Goal A): guest verifies compact cert binding Q/A/id + short Nat fragment.
//! Host coqchk is offline dual-path only — not settlement TCB.

pub mod acceptance;
pub mod exact_cert;
pub mod nat_expr;
pub mod parse;

pub use acceptance::{
    check_development, check_with_tier1_cert, AcceptanceBackend, AcceptanceError, CheckReport,
    CoqchkPortable, NatTargetFragment,
};
pub use exact_cert::{
    build as build_tier1_cert, encode as encode_tier1_cert, verify_against_inputs as verify_tier1_cert,
    CertError, Tier1Cert, CERT_LEN, FLAG_PLACEHOLDER, MAGIC, VERSION,
};
