//! Comment strip + lightweight Coq lexer/parsers for the Target acceptance fragment.
//!
//! Strips nested `(* ... *)` comments before tokenizing so forbidden vernacular and shape
//! checks are **not** fooled by comment text.
//!
//! NatExpr precedence: `*` binds tighter than `+`; both left-assoc. Parens override.

use crate::nat_expr::NatExpr;

/// Strip Coq block comments `(* ... *)`. Nested comments are handled.
pub fn strip_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut depth = 0usize;
    while i < bytes.len() {
        if depth > 0 {
            if i + 1 < bytes.len() && bytes[i] == b'(' && bytes[i + 1] == b'*' {
                depth += 1;
                i += 2;
                continue;
            }
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b')' {
                depth -= 1;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'(' && bytes[i + 1] == b'*' {
            depth = 1;
            i += 2;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Token kinds we care about (identifiers, numerals, punctuation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Ident(String),
    Num(u128),
    Plus,
    Star,
    Colon,
    ColonEq,
    Dot,
    Comma,
    Eq,
    LParen,
    RParen,
    Underscore,
    At,
}

/// Lex after comment strip. Identifiers are contiguous ASCII alnum/`_`/`'`.
pub fn lex(input: &str) -> Result<Vec<Tok>, &'static str> {
    let s = strip_comments(input);
    let bytes = s.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // multi-char :=
        if c == b':' && i + 1 < bytes.len() && bytes[i + 1] == b'=' {
            toks.push(Tok::ColonEq);
            i += 2;
            continue;
        }
        match c {
            b'+' => {
                toks.push(Tok::Plus);
                i += 1;
            }
            b'*' => {
                toks.push(Tok::Star);
                i += 1;
            }
            b':' => {
                toks.push(Tok::Colon);
                i += 1;
            }
            b'.' => {
                toks.push(Tok::Dot);
                i += 1;
            }
            b',' => {
                toks.push(Tok::Comma);
                i += 1;
            }
            b'=' => {
                toks.push(Tok::Eq);
                i += 1;
            }
            b'(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            b'_' => {
                if i + 1 < bytes.len()
                    && (bytes[i + 1].is_ascii_alphanumeric()
                        || bytes[i + 1] == b'_'
                        || bytes[i + 1] == b'\'')
                {
                    let start = i;
                    i += 1;
                    while i < bytes.len()
                        && (bytes[i].is_ascii_alphanumeric()
                            || bytes[i] == b'_'
                            || bytes[i] == b'\'')
                    {
                        i += 1;
                    }
                    toks.push(Tok::Ident(s[start..i].to_string()));
                } else {
                    toks.push(Tok::Underscore);
                    i += 1;
                }
            }
            b'@' => {
                toks.push(Tok::At);
                i += 1;
            }
            b'0'..=b'9' => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let n: u128 = s[start..i]
                    .parse()
                    .map_err(|_| "parse: numeral too large")?;
                toks.push(Tok::Num(n));
            }
            b'A'..=b'Z' | b'a'..=b'z' => {
                let start = i;
                i += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'\'')
                {
                    i += 1;
                }
                toks.push(Tok::Ident(s[start..i].to_string()));
            }
            // Skip other punctuation / symbols we don't need
            _ => {
                i += 1;
            }
        }
    }
    Ok(toks)
}

const FORBIDDEN: &[&str] = &[
    "Admitted",
    "Axiom",
    "Parameter",
    "Conjecture",
    "Hypothesis",
];

/// Reject if any **lexer token** matches a forbidden vernacular (not comment text).
pub fn reject_forbidden_tokens(toks: &[Tok]) -> Result<(), &'static str> {
    for t in toks {
        if let Tok::Ident(id) = t {
            if FORBIDDEN.iter().any(|f| *f == id.as_str()) {
                return Err("acceptance: forbidden vernacular token (Admitted/Axiom/Parameter/Conjecture/Hypothesis)");
            }
        }
    }
    Ok(())
}

struct Parser<'a> {
    toks: &'a [Tok],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(toks: &'a [Tok]) -> Self {
        Self { toks, i: 0 }
    }

    fn peek(&self) -> Option<&'a Tok> {
        self.toks.get(self.i)
    }

    fn bump(&mut self) -> Option<&'a Tok> {
        let t = self.toks.get(self.i)?;
        self.i += 1;
        Some(t)
    }

    fn eat_ident(&mut self, want: &str) -> bool {
        match self.peek() {
            Some(Tok::Ident(id)) if id == want => {
                self.i += 1;
                true
            }
            _ => false,
        }
    }

    fn eat(&mut self, kind: &Tok) -> bool {
        match self.peek() {
            Some(t) if tok_eq(t, kind) => {
                self.i += 1;
                true
            }
            _ => false,
        }
    }

    /// Parse NatExpr: additive, left-assoc; `*` tighter than `+`.
    fn parse_nat_expr(&mut self) -> Result<NatExpr, &'static str> {
        let mut left = self.parse_nat_term()?;
        while self.eat(&Tok::Plus) {
            let right = self.parse_nat_term()?;
            left = NatExpr::Add(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_nat_term(&mut self) -> Result<NatExpr, &'static str> {
        let mut left = self.parse_nat_atom()?;
        while self.eat(&Tok::Star) {
            let right = self.parse_nat_atom()?;
            left = NatExpr::Mul(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_nat_atom(&mut self) -> Result<NatExpr, &'static str> {
        match self.bump() {
            Some(Tok::Num(n)) => Ok(NatExpr::Lit(*n)),
            Some(Tok::Ident(id)) if id == "O" => Ok(NatExpr::Lit(0)),
            Some(Tok::Ident(id)) if id == "S" => {
                let inner = self.parse_nat_atom()?;
                Ok(NatExpr::Succ(Box::new(inner)))
            }
            Some(Tok::LParen) => {
                let e = self.parse_nat_expr()?;
                if !self.eat(&Tok::RParen) {
                    return Err("parse: expected ')' in NatExpr");
                }
                Ok(e)
            }
            _ => Err("parse: expected NatExpr atom"),
        }
    }
}

fn tok_eq(a: &Tok, b: &Tok) -> bool {
    match (a, b) {
        (Tok::Plus, Tok::Plus)
        | (Tok::Star, Tok::Star)
        | (Tok::Colon, Tok::Colon)
        | (Tok::ColonEq, Tok::ColonEq)
        | (Tok::Dot, Tok::Dot)
        | (Tok::Comma, Tok::Comma)
        | (Tok::Eq, Tok::Eq)
        | (Tok::LParen, Tok::LParen)
        | (Tok::RParen, Tok::RParen)
        | (Tok::Underscore, Tok::Underscore)
        | (Tok::At, Tok::At) => true,
        (Tok::Ident(x), Tok::Ident(y)) => x == y,
        (Tok::Num(x), Tok::Num(y)) => x == y,
        _ => false,
    }
}

/// Parsed Target shape (primary exists, or alternate eq-of-two-exprs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetShape {
    /// `exists n : nat, <expr> = n`
    Exists { expr: NatExpr },
    /// `<left> = <right>` (both NatExpr)
    Eq { left: NatExpr, right: NatExpr },
}

/// Extract Target from question tokens. Tries primary exists shape, then eq shape.
pub fn parse_target(toks: &[Tok]) -> Result<TargetShape, &'static str> {
    let mut i = 0;
    while i + 5 < toks.len() {
        if matches!(&toks[i], Tok::Ident(id) if id == "Definition")
            && matches!(&toks[i + 1], Tok::Ident(id) if id == "Target")
            && matches!(&toks[i + 2], Tok::Colon)
            && matches!(&toks[i + 3], Tok::Ident(id) if id == "Prop")
            && matches!(&toks[i + 4], Tok::ColonEq)
        {
            let rest = &toks[i + 5..];
            // Primary: exists n : nat, <expr> = n
            if matches!(rest.first(), Some(Tok::Ident(id)) if id == "exists") {
                let mut p = Parser::new(&rest[1..]);
                match p.bump() {
                    Some(Tok::Ident(_)) => {}
                    _ => return Err("parse: Target exists binder"),
                }
                if !p.eat(&Tok::Colon) {
                    return Err("parse: Target expected ':' after binder");
                }
                if !p.eat_ident("nat") {
                    return Err("parse: Target expected 'nat'");
                }
                if !p.eat(&Tok::Comma) {
                    return Err("parse: Target expected ','");
                }
                let expr = p.parse_nat_expr()?;
                if !p.eat(&Tok::Eq) {
                    return Err("parse: Target expected '='");
                }
                match p.bump() {
                    Some(Tok::Ident(_)) => {}
                    _ => return Err("parse: Target expected binder on RHS of '='"),
                }
                return Ok(TargetShape::Exists { expr });
            }
            // Alternate: <NatExpr> = <NatExpr>
            let mut p = Parser::new(rest);
            let left = p.parse_nat_expr()?;
            if !p.eat(&Tok::Eq) {
                return Err("parse: Target eq-shape expected '='");
            }
            let right = p.parse_nat_expr()?;
            return Ok(TargetShape::Eq { left, right });
        }
        i += 1;
    }
    Err("parse: Definition Target : Prop := … not found")
}

/// Extract NatExpr from primary exists Target (compat helper).
pub fn parse_target_nat_expr(toks: &[Tok]) -> Result<NatExpr, &'static str> {
    match parse_target(toks)? {
        TargetShape::Exists { expr } => Ok(expr),
        TargetShape::Eq { .. } => Err("parse: expected exists Target shape, got eq-shape"),
    }
}

/// Parse `Definition visible_result : nat := <lit>.` or `Definition visible_result := <lit>.`
pub fn parse_visible_result_lit(toks: &[Tok]) -> Result<u32, &'static str> {
    let mut i = 0;
    while i + 2 < toks.len() {
        if matches!(&toks[i], Tok::Ident(id) if id == "Definition")
            && matches!(&toks[i + 1], Tok::Ident(id) if id == "visible_result")
        {
            let mut j = i + 2;
            if matches!(toks.get(j), Some(Tok::Colon)) {
                j += 1;
                if !matches!(toks.get(j), Some(Tok::Ident(id)) if id == "nat") {
                    return Err("parse: visible_result expected 'nat' after ':'");
                }
                j += 1;
            }
            if !matches!(toks.get(j), Some(Tok::ColonEq)) {
                return Err("parse: visible_result expected ':='");
            }
            j += 1;
            let lit = match toks.get(j) {
                Some(Tok::Num(n)) => {
                    u32::try_from(*n).map_err(|_| "parse: visible_result lit > u32")?
                }
                Some(Tok::Ident(id)) if id == "O" => 0u32,
                _ => return Err("parse: visible_result expected numeral"),
            };
            return Ok(lit);
        }
        i += 1;
    }
    Err("parse: Definition visible_result := <lit> not found")
}

/// Evidence that exists-Target is inhabited via `ex_intro` + same lit + `eq_refl`.
pub fn find_ex_intro_lit_with_eq_refl(toks: &[Tok]) -> Result<u32, &'static str> {
    let mut i = 0;
    while i < toks.len() {
        if matches!(&toks[i], Tok::Ident(id) if id == "ex_intro") {
            let mut j = i + 1;
            let mut lit: Option<u32> = None;
            let mut saw_eq_refl = false;
            let limit = (i + 32).min(toks.len());
            while j < limit {
                match &toks[j] {
                    Tok::Num(n) if lit.is_none() => {
                        lit = Some(
                            u32::try_from(*n).map_err(|_| "parse: ex_intro lit > u32")?,
                        );
                    }
                    Tok::Ident(id) if id == "eq_refl" => {
                        saw_eq_refl = true;
                        break;
                    }
                    Tok::Ident(id)
                        if id == "Definition"
                            || id == "Theorem"
                            || id == "Qed"
                            || id == "Proof" =>
                    {
                        break;
                    }
                    _ => {}
                }
                j += 1;
            }
            if let (Some(n), true) = (lit, saw_eq_refl) {
                return Ok(n);
            }
        }
        i += 1;
    }
    Err("parse: ex_intro <lit> eq_refl evidence not found")
}

/// Evidence for eq-shape Target: bare `eq_refl`, `exact eq_refl`, or `:= eq_refl`.
pub fn find_eq_refl_evidence(toks: &[Tok]) -> Result<(), &'static str> {
    for t in toks {
        if matches!(t, Tok::Ident(id) if id == "eq_refl") {
            return Ok(());
        }
    }
    Err("parse: eq_refl evidence not found for eq-shape Target")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_nested_and_forbidden_in_comment_ok() {
        let src = "(* Admitted *) Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let toks = lex(src).unwrap();
        assert!(reject_forbidden_tokens(&toks).is_ok());
        let e = parse_target_nat_expr(&toks).unwrap();
        assert_eq!(e.eval_u32().unwrap(), 2);
    }

    #[test]
    fn admitted_token_rejected() {
        let src = "Definition visible_result : nat := 2. Theorem t. Admitted.";
        let toks = lex(src).unwrap();
        assert!(reject_forbidden_tokens(&toks).is_err());
    }

    #[test]
    fn parse_mul_and_precedence() {
        let toks = lex("Definition Target : Prop := exists n : nat, 1 + 2 * 3 = n.").unwrap();
        let e = parse_target_nat_expr(&toks).unwrap();
        assert_eq!(e.eval_u32().unwrap(), 7);
    }

    #[test]
    fn parse_two_times_three() {
        let toks = lex("Definition Target : Prop := exists n : nat, 2 * 3 = n.").unwrap();
        let e = parse_target_nat_expr(&toks).unwrap();
        assert_eq!(e.eval_u32().unwrap(), 6);
    }

    #[test]
    fn parse_parens_and_succ() {
        let toks = lex("Definition Target : Prop := exists n : nat, (1 + 1) + 1 = n.").unwrap();
        assert_eq!(parse_target_nat_expr(&toks).unwrap().eval_u32().unwrap(), 3);
        let toks2 = lex("Definition Target : Prop := exists n : nat, S (S O) = n.").unwrap();
        assert_eq!(parse_target_nat_expr(&toks2).unwrap().eval_u32().unwrap(), 2);
    }

    #[test]
    fn parse_eq_shape() {
        let toks = lex("Definition Target : Prop := 1 + 1 = 2.").unwrap();
        match parse_target(&toks).unwrap() {
            TargetShape::Eq { left, right } => {
                assert_eq!(left.eval_u32().unwrap(), 2);
                assert_eq!(right.eval_u32().unwrap(), 2);
            }
            other => panic!("expected Eq, got {:?}", other),
        }
    }
}
