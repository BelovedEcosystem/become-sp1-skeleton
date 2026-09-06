//! NatExpr AST + evaluator for the BECOME Target shape fragment.
//!
//! # Grammar (widened)
//!
//! ```text
//! expr  ::= term ('+' term)*          (* left-assoc *)
//! term  ::= atom ('*' atom)*          (* left-assoc; * binds tighter than + *)
//! atom  ::= lit | 'O' | 'S' atom | '(' expr ')'
//! lit   ::= 0 | 1 | 2 | ...
//! ```
//!
//! Precedence: `*` binds tighter than `+`. Both are left-associative.
//! Use parentheses to override (e.g. `(1+1)*2`).
//!
//! Supported examples: `1+1`, `2*3`, `(1+1)+1`, `S (S O)`.
//!
//! Eval to `u128` with checked arithmetic; narrowing to `u32` errors on overflow.
//! **Not** full coqchk — real Gallina fragment evaluator only.

/// A natural-number expression extracted from a Target definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatExpr {
    Lit(u128),
    Succ(Box<NatExpr>),
    Add(Box<NatExpr>, Box<NatExpr>),
    Mul(Box<NatExpr>, Box<NatExpr>),
}

impl NatExpr {
    /// Evaluate to `u128` (checked; overflow → error).
    pub fn eval_u128(&self) -> Result<u128, &'static str> {
        match self {
            NatExpr::Lit(n) => Ok(*n),
            NatExpr::Succ(e) => e
                .eval_u128()?
                .checked_add(1)
                .ok_or("nat_expr: S overflow"),
            NatExpr::Add(a, b) => a
                .eval_u128()?
                .checked_add(b.eval_u128()?)
                .ok_or("nat_expr: + overflow"),
            NatExpr::Mul(a, b) => a
                .eval_u128()?
                .checked_mul(b.eval_u128()?)
                .ok_or("nat_expr: * overflow"),
        }
    }

    /// Evaluate and narrow to `u32` (fail closed on overflow).
    pub fn eval_u32(&self) -> Result<u32, &'static str> {
        let v = self.eval_u128()?;
        u32::try_from(v).map_err(|_| "nat_expr: result does not fit in u32")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_one_plus_one() {
        let e = NatExpr::Add(Box::new(NatExpr::Lit(1)), Box::new(NatExpr::Lit(1)));
        assert_eq!(e.eval_u32().unwrap(), 2);
    }

    #[test]
    fn eval_two_times_three() {
        let e = NatExpr::Mul(Box::new(NatExpr::Lit(2)), Box::new(NatExpr::Lit(3)));
        assert_eq!(e.eval_u32().unwrap(), 6);
    }

    #[test]
    fn eval_succ() {
        let e = NatExpr::Succ(Box::new(NatExpr::Succ(Box::new(NatExpr::Lit(0)))));
        assert_eq!(e.eval_u32().unwrap(), 2);
    }

    #[test]
    fn mul_binds_tighter() {
        // 1 + 2 * 3 = 1 + 6 = 7
        let e = NatExpr::Add(
            Box::new(NatExpr::Lit(1)),
            Box::new(NatExpr::Mul(Box::new(NatExpr::Lit(2)), Box::new(NatExpr::Lit(3)))),
        );
        assert_eq!(e.eval_u32().unwrap(), 7);
    }

    #[test]
    fn mul_overflow_errors() {
        let e = NatExpr::Mul(Box::new(NatExpr::Lit(u128::MAX)), Box::new(NatExpr::Lit(2)));
        assert!(e.eval_u128().is_err());
    }
}
