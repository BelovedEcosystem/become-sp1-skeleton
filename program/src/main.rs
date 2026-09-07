//! SP1 skeleton guest — Tier-2 T2CERT0 path (WP3).
//! Reads id + visible + question/answer + T2 cert + canonical ok_lines.
//! Verifies cert fail-closed, then short Nat fragment. NOT full coqchk in-guest.
//! programVKey is from THIS skeleton ELF only.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol, SolValue};
use skeleton_commit_program::check_with_tier2_cert;

sol! {
    /// Matches Solidity `abi.decode(publicValues, (bytes32, uint32))`.
    struct PublicValues {
        bytes32 id;
        uint32 visibleResult;
    }
}

pub fn main() {
    let id: [u8; 32] = sp1_zkvm::io::read();
    let visible_result: u32 = sp1_zkvm::io::read();
    let question: Vec<u8> = sp1_zkvm::io::read_vec();
    let answer: Vec<u8> = sp1_zkvm::io::read_vec();
    let cert: Vec<u8> = sp1_zkvm::io::read_vec();
    // Canonical ok_lines blob for safe_ok_digest recomputation (host-sorted).
    let ok_lines: Vec<u8> = sp1_zkvm::io::read_vec();

    match check_with_tier2_cert(
        &question,
        &answer,
        visible_result,
        &id,
        &cert,
        &ok_lines,
    ) {
        Ok(_report) => {}
        Err(e) => panic!("{}", e.as_str()),
    }

    let encoded = PublicValues {
        id: id.into(),
        visibleResult: visible_result,
    }
    .abi_encode();

    sp1_zkvm::io::commit_slice(&encoded);
}
