//! Acceptance kernel fragment for the BECOME Target shape (SP1 guest shared logic).
//!
//! **Not** full `coqchk` / Rocq kernel (OCaml Coq cannot run inside SP1 today).
//! **Is** a real NatExpr evaluator + proof-shape checker for:
//! - `Target := exists n : nat, <NatExpr> = n` inhabited by `ex_intro _ n eq_refl`
//! - `Target := <NatExpr> = <NatExpr>` inhabited by `eq_refl`
//!
//! NatExpr: lit / `O` / `S e` / `(e)` / `e + e` / `e * e` (`*` tighter than `+`, left-assoc).

pub mod acceptance;
pub mod nat_expr;
pub mod parse;

pub use acceptance::{
    check_development, AcceptanceBackend, AcceptanceError, CheckReport, CoqchkPortable,
    NatTargetFragment,
};
