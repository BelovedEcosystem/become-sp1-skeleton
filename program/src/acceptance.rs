//! # Acceptance kernel fragment (NOT full coqchk)
//!
//! This is **not** full `coqchk` / Rocq kernel — OCaml Coq cannot run inside SP1 today.
//! It **is** a real evaluator + proof-shape checker for Gallina Target fragments:
//!
//! 1. **Primary:** `Target := exists n : nat, <NatExpr> = n` inhabited by
//!    `ex_intro _ <n> eq_refl` with `visible_result = n` and `eval(<NatExpr>) = n`.
//! 2. **Alternate:** `Target := <NatExpr> = <NatExpr>` inhabited by bare / exact
//!    `eq_refl` (or `Definition answer : Target := eq_refl`) with both sides equal
//!    and visible matching that value.
//!
//! Architecture: guest calls only [`check_development`], which delegates to
//! [`NatTargetFragment`]. When a portable `coqchk` ELF exists, swap
//! [`CoqchkPortable`] in via [`AcceptanceBackend`].

use crate::parse::{
    find_eq_refl_evidence, find_ex_intro_lit_with_eq_refl, lex, parse_target,
    parse_visible_result_lit, reject_forbidden_tokens, TargetShape,
};

/// Successful acceptance report (semantic eval + committed visible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    pub nat_expr_eval: u32,
    pub visible: u32,
}

/// Structured acceptance failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceError {
    EmptyQuestion,
    EmptyAnswer,
    Utf8,
    /// Portable coqchk backend not available in this guest build.
    NotAvailable,
    Message(&'static str),
}

impl AcceptanceError {
    pub fn as_str(&self) -> &'static str {
        match self {
            AcceptanceError::EmptyQuestion => "acceptance: question must be non-empty",
            AcceptanceError::EmptyAnswer => "acceptance: answer must be non-empty",
            AcceptanceError::Utf8 => "acceptance: input is not valid UTF-8",
            AcceptanceError::NotAvailable => {
                "acceptance: coqchk portable backend not available (NOT full coqchk)"
            }
            AcceptanceError::Message(m) => m,
        }
    }
}

impl core::fmt::Display for AcceptanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn bytes_to_str(b: &[u8]) -> Result<&str, AcceptanceError> {
    core::str::from_utf8(b).map_err(|_| AcceptanceError::Utf8)
}

/// Swap point for acceptance backends (Nat fragment today; coqchk later).
pub trait AcceptanceBackend {
    fn check(
        &self,
        question: &[u8],
        answer: &[u8],
        visible: u32,
    ) -> Result<CheckReport, AcceptanceError>;
}

/// Current guest backend: widened NatExpr Target fragment (NOT full coqchk).
pub struct NatTargetFragment;

impl AcceptanceBackend for NatTargetFragment {
    fn check(
        &self,
        question: &[u8],
        answer: &[u8],
        visible: u32,
    ) -> Result<CheckReport, AcceptanceError> {
        check_nat_target_fragment(question, answer, visible)
    }
}

/// Future portable coqchk / Rocq kernel port. Always returns [`AcceptanceError::NotAvailable`]
/// until a real port exists. Do **not** claim this is coqchk.
pub struct CoqchkPortable;

impl AcceptanceBackend for CoqchkPortable {
    fn check(
        &self,
        _question: &[u8],
        _answer: &[u8],
        _visible: u32,
    ) -> Result<CheckReport, AcceptanceError> {
        Err(AcceptanceError::NotAvailable)
    }
}

/// Real semantic acceptance for Nat Target shapes (fragment — not coqchk).
///
/// Checks:
/// 1. Non-empty UTF-8 question/answer; strip comments then lex.
/// 2. No forbidden vernacular tokens on **question and answer** (lexer, not comment).
/// 3. Question defines Target (exists shape **or** eq-of-exprs shape); eval.
/// 4. Answer has `Definition visible_result ... := <lit>` with lit == `visible`.
/// 5. Shape-appropriate evidence (`ex_intro`+`eq_refl` or bare/`exact` `eq_refl`).
/// 6. **Semantic:** eval matches visible (and both sides equal for eq-shape).
pub fn check_nat_target_fragment(
    question: &[u8],
    answer: &[u8],
    visible: u32,
) -> Result<CheckReport, AcceptanceError> {
    if question.is_empty() {
        return Err(AcceptanceError::EmptyQuestion);
    }
    if answer.is_empty() {
        return Err(AcceptanceError::EmptyAnswer);
    }

    let q_str = bytes_to_str(question)?;
    let a_str = bytes_to_str(answer)?;

    let q_toks = lex(q_str).map_err(AcceptanceError::Message)?;
    let a_toks = lex(a_str).map_err(AcceptanceError::Message)?;

    // Forbidden vernacular on question **and** answer (fail closed either side).
    reject_forbidden_tokens(&q_toks).map_err(AcceptanceError::Message)?;
    reject_forbidden_tokens(&a_toks).map_err(AcceptanceError::Message)?;

    let shape = parse_target(&q_toks).map_err(AcceptanceError::Message)?;

    let visible_lit = parse_visible_result_lit(&a_toks).map_err(AcceptanceError::Message)?;
    if visible_lit != visible {
        return Err(AcceptanceError::Message(
            "acceptance: visible_result lit ≠ committed visible",
        ));
    }

    let nat_expr_eval = match shape {
        TargetShape::Exists { expr } => {
            let nat_expr_eval = expr.eval_u32().map_err(AcceptanceError::Message)?;
            let ex_lit =
                find_ex_intro_lit_with_eq_refl(&a_toks).map_err(AcceptanceError::Message)?;
            if ex_lit != visible {
                return Err(AcceptanceError::Message(
                    "acceptance: ex_intro numeral ≠ committed visible",
                ));
            }
            if nat_expr_eval != visible {
                return Err(AcceptanceError::Message(
                    "acceptance: eval(NatExpr) ≠ visible (semantic mismatch)",
                ));
            }
            nat_expr_eval
        }
        TargetShape::Eq { left, right } => {
            find_eq_refl_evidence(&a_toks).map_err(AcceptanceError::Message)?;
            let left_v = left.eval_u32().map_err(AcceptanceError::Message)?;
            let right_v = right.eval_u32().map_err(AcceptanceError::Message)?;
            if left_v != right_v {
                return Err(AcceptanceError::Message(
                    "acceptance: eq-shape LHS eval ≠ RHS eval",
                ));
            }
            // Both sides equal; visible must match that value.
            // (Also covers: RHS lit matching visible and LHS eval == visible.)
            if left_v != visible {
                return Err(AcceptanceError::Message(
                    "acceptance: eq-shape eval ≠ visible (semantic mismatch)",
                ));
            }
            left_v
        }
    };

    Ok(CheckReport {
        nat_expr_eval,
        visible,
    })
}

/// Guest entrypoint — delegates to [`NatTargetFragment`].
///
/// When swapping backends, change only this delegation (or inject via a static).
pub fn check_development(
    question: &[u8],
    answer: &[u8],
    visible: u32,
) -> Result<CheckReport, AcceptanceError> {
    NatTargetFragment.check(question, answer, visible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn job_bytes(name: &str) -> Vec<u8> {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("../../jobs/yaa-1plus1-zkp");
        p.push(name);
        fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    fn fixture(dir: &str, name: &str) -> Vec<u8> {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests/fixtures");
        p.push(dir);
        p.push(name);
        fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    #[test]
    fn real_question_answer_ok_eval_2() {
        let q = job_bytes("Question.v");
        let a = job_bytes("answer.v");
        let r = check_development(&q, &a, 2).expect("real files should pass");
        assert_eq!(r.nat_expr_eval, 2);
        assert_eq!(r.visible, 2);
    }

    #[test]
    fn visible_3_with_one_plus_one_fails() {
        let q = job_bytes("Question.v");
        let a = b"Definition answer : Target := ex_intro _ 3 eq_refl.\n\
                  Definition visible_result : nat := 3.\n";
        let err = check_development(&q, a, 3).unwrap_err();
        assert!(
            err.as_str().contains("semantic") || err.as_str().contains("eval"),
            "got: {}",
            err.as_str()
        );
    }

    #[test]
    fn ex_intro_3_visible_3_but_expr_1plus1_fails_semantic() {
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition answer : Target := ex_intro _ 3 eq_refl.\n\
                  Definition visible_result : nat := 3.\n";
        let err = check_development(q, a, 3).unwrap_err();
        assert!(
            err.as_str().contains("semantic") || err.as_str().contains("eval"),
            "got: {}",
            err.as_str()
        );
    }

    #[test]
    fn admitted_in_answer_fails() {
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition visible_result : nat := 2.\n\
                  Definition answer : Target := ex_intro _ 2 eq_refl.\n\
                  Theorem bad : True. Admitted.\n";
        let err = check_development(q, a, 2).unwrap_err();
        assert!(err.as_str().contains("forbidden"), "got: {}", err.as_str());
    }

    #[test]
    fn admitted_in_question_fails() {
        let q = b"Axiom bad : True. Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition answer : Target := ex_intro _ 2 eq_refl.\n\
                  Definition visible_result : nat := 2.\n";
        let err = check_development(q, a, 2).unwrap_err();
        assert!(err.as_str().contains("forbidden"), "got: {}", err.as_str());
    }

    #[test]
    fn missing_eq_refl_fails() {
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition visible_result : nat := 2.\n\
                  Definition answer : Target := ex_intro _ 2 I.\n";
        let err = check_development(q, a, 2).unwrap_err();
        assert!(
            err.as_str().contains("ex_intro") || err.as_str().contains("eq_refl"),
            "got: {}",
            err.as_str()
        );
    }

    #[test]
    fn missing_ex_intro_fails_on_exists_shape() {
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition visible_result : nat := 2.\n\
                  Definition answer : Target := eq_refl.\n";
        let err = check_development(q, a, 2).unwrap_err();
        assert!(
            err.as_str().contains("ex_intro") || err.as_str().contains("eq_refl"),
            "got: {}",
            err.as_str()
        );
    }

    #[test]
    fn happy_minimal_bytes() {
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition answer : Target := ex_intro _ 2 eq_refl.\n\
                  Definition visible_result : nat := 2.\n";
        let r = check_development(q, a, 2).unwrap();
        assert_eq!(r.nat_expr_eval, 2);
    }

    #[test]
    fn ex_intro_numeral_mismatch_visible_fails() {
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition answer : Target := ex_intro _ 3 eq_refl.\n\
                  Definition visible_result : nat := 2.\n";
        let err = check_development(q, a, 2).unwrap_err();
        assert!(
            err.as_str().contains("ex_intro"),
            "got: {}",
            err.as_str()
        );
    }

    #[test]
    fn admitted_only_in_comment_ok() {
        let q = b"(* Admitted *) Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"(* Axiom *) Definition answer : Target := ex_intro _ 2 eq_refl.\n\
                  Definition visible_result : nat := 2.\n";
        assert!(check_development(q, a, 2).is_ok());
    }

    #[test]
    fn mul_target_fixture_ok() {
        let q = fixture("mul_target", "Question.v");
        let a = fixture("mul_target", "answer.v");
        let r = check_development(&q, &a, 6).expect("mul_target");
        assert_eq!(r.nat_expr_eval, 6);
    }

    #[test]
    fn mul_wrong_visible_fails() {
        let q = fixture("mul_target", "Question.v");
        let a = b"Definition answer : Target := ex_intro _ 5 eq_refl.\n\
                  Definition visible_result : nat := 5.\n";
        let err = check_development(&q, a, 5).unwrap_err();
        assert!(
            err.as_str().contains("semantic") || err.as_str().contains("eval"),
            "got: {}",
            err.as_str()
        );
    }

    #[test]
    fn eq_shape_fixture_ok() {
        let q = fixture("eq_shape", "Question.v");
        let a = fixture("eq_shape", "answer.v");
        let r = check_development(&q, &a, 2).expect("eq_shape");
        assert_eq!(r.nat_expr_eval, 2);
    }

    #[test]
    fn eq_shape_wrong_visible_fails() {
        let q = b"Definition Target : Prop := 1 + 1 = 2.";
        let a = b"Definition answer : Target := eq_refl.\n\
                  Definition visible_result : nat := 3.\n";
        let err = check_development(q, a, 3).unwrap_err();
        assert!(
            err.as_str().contains("semantic")
                || err.as_str().contains("eval")
                || err.as_str().contains("visible"),
            "got: {}",
            err.as_str()
        );
    }

    #[test]
    fn eq_shape_unequal_sides_fails() {
        let q = b"Definition Target : Prop := 1 + 1 = 3.";
        let a = b"Definition answer : Target := eq_refl.\n\
                  Definition visible_result : nat := 2.\n";
        let err = check_development(q, a, 2).unwrap_err();
        assert!(
            err.as_str().contains("LHS") || err.as_str().contains("eq-shape"),
            "got: {}",
            err.as_str()
        );
    }

    #[test]
    fn eq_shape_exact_eq_refl_qed() {
        let q = b"Definition Target : Prop := 2 * 3 = 6.";
        let a = b"Theorem answer : Target. Proof. exact eq_refl. Qed.\n\
                  Definition visible_result : nat := 6.\n";
        let r = check_development(q, a, 6).unwrap();
        assert_eq!(r.nat_expr_eval, 6);
    }

    #[test]
    fn coqchk_portable_not_available() {
        let err = CoqchkPortable
            .check(b"x", b"y", 0)
            .unwrap_err();
        assert_eq!(err, AcceptanceError::NotAvailable);
    }

    #[test]
    fn backend_trait_delegates() {
        let q = b"Definition Target : Prop := exists n : nat, S (S O) = n.";
        let a = b"Definition answer : Target := ex_intro _ 2 eq_refl.\n\
                  Definition visible_result : nat := 2.\n";
        let r = NatTargetFragment.check(q, a, 2).unwrap();
        assert_eq!(r.nat_expr_eval, 2);
    }
}
