//! NON-BECOME SP1 skeleton guest.
//! Reads placeholder `bytes32` id + `u32` visible_result + question/answer bytes,
//! runs the **acceptance kernel fragment** (NOT full coqchk), then commits
//! ABI-encoded `(bytes32,uint32)`.
//!
//! NOT BECOME acceptance / coqchk guest. Placeholder id ≠ official jobHash.
//! programVKey is from THIS skeleton ELF only — do not treat as official BECOME vkey.
//!
//! Guest calls `check_development` → `NatTargetFragment`. When a portable coqchk
//! ELF exists, swap via `AcceptanceBackend` / `CoqchkPortable`; entrypoint stays.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol, SolValue};
use skeleton_commit_program::check_development;

sol! {
    /// Matches Solidity `abi.decode(publicValues, (bytes32, uint32))`.
    struct PublicValues {
        bytes32 id;
        uint32 visibleResult;
    }
}

pub fn main() {
    // Host writes: id ([u8;32]), visible_result (u32), question (Vec<u8>), answer (Vec<u8>).
    let id: [u8; 32] = sp1_zkvm::io::read();
    let visible_result: u32 = sp1_zkvm::io::read();
    let question: Vec<u8> = sp1_zkvm::io::read_vec();
    let answer: Vec<u8> = sp1_zkvm::io::read_vec();

    // Acceptance kernel fragment — real NatExpr eval + Target proof-shape (NOT full coqchk).
    match check_development(&question, &answer, visible_result) {
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
