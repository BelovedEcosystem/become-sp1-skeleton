//! NON-BECOME SP1 skeleton guest (Goal A Tier-1 cert path).
//! Reads id + visible + question/answer + Tier-1 cert bytes.
//! Verifies cert (bind Q/A/id) fail-closed, then short Nat fragment.
//! NOT full coqchk. Placeholder id ≠ official jobHash.
//! programVKey is from THIS skeleton ELF only.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol, SolValue};
use skeleton_commit_program::check_with_tier1_cert;

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
    // Goal A: compact exact certificate — empty ⇒ fail-closed (never Valid).
    let cert: Vec<u8> = sp1_zkvm::io::read_vec();

    match check_with_tier1_cert(&question, &answer, visible_result, &id, &cert) {
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
