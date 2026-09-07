//! Host: setup + prove for NON-BECOME skeleton-commit guest (acceptance kernel fragment).
//! Writes proof.bin, public_values.bin, vkey.txt, meta.json under --out.
//! NOT full coqchk / Rocq kernel. Placeholder id ≠ official jobHash.
//! Guest runs real NatExpr eval + Target proof-shape checker (not a string-contains toy).

use alloy_sol_types::{sol, SolValue};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Same acceptance API as the guest (host preflight + unit tests).
use skeleton_commit_program::{build_tier1_cert, check_development, encode_tier1_cert};

const ELF: Elf = include_elf!("skeleton-commit-program");

/// keccak256("skeleton-1plus1-NON-BECOME") — interim placeholder, NOT official jobHash.
const DEFAULT_ID_HEX: &str = "095aac19877dbee967552bc0ea86dd8f6796727e55f4d0338453021c37160076";

sol! {
    struct PublicValues {
        bytes32 id;
        uint32 visibleResult;
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum ProofSystem {
    Groth16,
    Compressed,
}

#[derive(Parser, Debug)]
#[command(about = "Prove NON-BECOME skeleton-commit guest with acceptance kernel fragment (NOT full coqchk)")]
struct Args {
    /// 32-byte id as 0x-prefixed or bare hex (placeholder ≠ official jobHash)
    #[arg(long, default_value = "")]
    id: String,

    #[arg(long, default_value_t = 2)]
    visible: u32,

    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem,

    #[arg(long, default_value = "../../jobs/skeleton-commit/sp1")]
    out: PathBuf,

    /// Question .v bytes (default: toy job Question.v)
    #[arg(long)]
    question: Option<PathBuf>,

    /// Answer .v bytes (default: toy job answer.v)
    #[arg(long)]
    answer: Option<PathBuf>,

    /// Require host coqc/coqchk on the job dir (default true). Fail closed if they fail.
    /// Defense in depth only — does NOT replace guest acceptance. Not full coqchk-in-guest.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    require_host_coqchk: bool,
}

#[derive(Serialize)]
struct Meta {
    proof_system: String,
    requested_system: String,
    fell_back_from_groth16: bool,
    vkey_bytes32: String,
    public_values_hex: String,
    id_hex: String,
    visible: u32,
    nat_expr_eval: u32,
    question_path: String,
    answer_path: String,
    question_byte_len: usize,
    answer_byte_len: usize,
    proof_byte_len: usize,
    note: String,
    docker_gap: String,
}

fn parse_id(s: &str) -> [u8; 32] {
    let raw = if s.is_empty() {
        DEFAULT_ID_HEX.to_string()
    } else {
        s.trim_start_matches("0x").to_string()
    };
    let bytes = hex::decode(&raw).expect("--id must be 32-byte hex");
    assert_eq!(bytes.len(), 32, "--id must be exactly 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn resolve_default_job_file(name: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let preferred = manifest.join("../../jobs/yaa-1plus1-zkp").join(name);
    if preferred.is_file() {
        return preferred;
    }
    let fallback = manifest.join("../../jobs/yaa-full-cycle").join(name);
    if fallback.is_file() {
        return fallback;
    }
    preferred
}

fn resolve_path(arg: &Path, default_name: &str) -> PathBuf {
    if arg.as_os_str().is_empty() {
        resolve_default_job_file(default_name)
    } else if arg.is_absolute() {
        arg.to_path_buf()
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(arg)
    }
}

fn read_required(path: &Path, label: &str) -> Vec<u8> {
    assert!(
        path.is_file(),
        "missing {label} file: {} (fail fast)",
        path.display()
    );
    fs::read(path).unwrap_or_else(|e| panic!("read {label} {}: {e}", path.display()))
}

/// Host coqc/coqchk defense-in-depth. Never replaces guest check. NOT coqchk-in-guest.
fn host_coqchk(question_path: &Path, answer_path: &Path, require: bool) {
    let Some(job_dir) = question_path.parent() else {
        if require {
            panic!("host coqchk: no parent dir for question");
        }
        eprintln!("warn: host coqchk: no parent dir for question");
        return;
    };
    if !answer_path.starts_with(job_dir) {
        if require {
            panic!(
                "host coqchk: answer not in same dir as question ({})",
                answer_path.display()
            );
        }
        eprintln!("warn: host coqchk: answer not in same dir as question; skipping");
        return;
    }
    let q_name = question_path.file_name().unwrap().to_str().unwrap();
    let coqc = Command::new("coqc")
        .current_dir(job_dir)
        .args(["-q", q_name])
        .output();
    match coqc {
        Ok(o) if o.status.success() => {
            println!("host coqc {q_name}: ok");
        }
        Ok(o) => {
            let msg = format!(
                "host coqc {q_name} failed (status={}): {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            );
            if require {
                panic!("{msg}");
            }
            eprintln!("warn: {msg}");
            return;
        }
        Err(e) => {
            if require {
                panic!("host coqc not runnable: {e}");
            }
            eprintln!("warn: host coqc not runnable: {e}");
            return;
        }
    }
    let ans_name = answer_path.file_name().unwrap().to_str().unwrap();
    let coqc_a = Command::new("coqc")
        .current_dir(job_dir)
        .args(["-q", ans_name])
        .output();
    match coqc_a {
        Ok(o) if o.status.success() => {
            println!("host coqc {ans_name}: ok");
        }
        Ok(o) => {
            let msg = format!(
                "host coqc {ans_name} failed (status={}): {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            );
            if require {
                panic!("{msg}");
            }
            eprintln!("warn: {msg}");
            return;
        }
        Err(e) => {
            if require {
                panic!("host coqc answer not runnable: {e}");
            }
            eprintln!("warn: host coqc answer not runnable: {e}");
            return;
        }
    }
    let stem = answer_path.file_stem().and_then(|s| s.to_str()).unwrap_or("answer");
    let vo = job_dir.join(format!("{stem}.vo"));
    if vo.is_file() {
        let chk = Command::new("coqchk")
            .current_dir(job_dir)
            .args(["-silent", "-o", stem])
            .output();
        match chk {
            Ok(o) if o.status.success() => println!("host coqchk {stem}: ok"),
            Ok(o) => {
                let msg = format!(
                    "host coqchk failed (status={}): {}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                );
                if require {
                    panic!("{msg}");
                }
                eprintln!("warn: {msg}");
            }
            Err(e) => {
                if require {
                    panic!("host coqchk not runnable: {e}");
                }
                eprintln!("warn: host coqchk not runnable: {e}");
            }
        }
    } else if require {
        panic!("host coqchk: missing {}.vo after coqc", stem);
    }
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();

    let out = if args.out.is_absolute() {
        args.out.clone()
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&args.out)
    };
    fs::create_dir_all(&out).expect("create out dir");

    let id = parse_id(&args.id);
    let question_path = match &args.question {
        Some(p) => resolve_path(p, "Question.v"),
        None => resolve_default_job_file("Question.v"),
    };
    let answer_path = match &args.answer {
        Some(p) => resolve_path(p, "answer.v"),
        None => resolve_default_job_file("answer.v"),
    };
    let question = read_required(&question_path, "question");
    let answer = read_required(&answer_path, "answer");

    // Host-side fail-closed preflight (same acceptance kernel as guest).
    let report = match check_development(&question, &answer, args.visible) {
        Ok(r) => r,
        Err(e) => panic!("acceptance preflight failed: {}", e.as_str()),
    };
    println!(
        "acceptance preflight ok: nat_expr_eval={} visible={}",
        report.nat_expr_eval, report.visible
    );

    host_coqchk(&question_path, &answer_path, args.require_host_coqchk);

    let client = ProverClient::from_env();
    let pk = client.setup(ELF).expect("setup");

    // Goal A Tier-1 cert: bind Q/A/id (fail-closed in guest if missing/placeholder).
    let tier1 = build_tier1_cert(id, &question, &answer, args.visible, report.nat_expr_eval);
    let cert_bytes = encode_tier1_cert(&tier1);
    fs::write(out.join("tier1_cert.bin"), &cert_bytes).expect("write tier1_cert.bin");
    println!(
        "tier1-cert: {} bytes (nat_expr_eval={})",
        cert_bytes.len(),
        report.nat_expr_eval
    );

    let mut stdin = SP1Stdin::new();
    stdin.write(&id);
    stdin.write(&args.visible);
    stdin.write_vec(question.clone());
    stdin.write_vec(answer.clone());
    stdin.write_vec(cert_bytes.to_vec());

    println!(
        "NON-BECOME skeleton prove (Tier-1 cert + Nat fragment, NOT full coqchk): system={:?} visible={} id=0x{}",
        args.system,
        args.visible,
        hex::encode(id)
    );
    println!("question={} ({} bytes)", question_path.display(), question.len());
    println!("answer={} ({} bytes)", answer_path.display(), answer.len());

    let mut fell_back = false;
    let (proof, used_system) = match args.system {
        ProofSystem::Groth16 => match client.prove(&pk, stdin.clone()).groth16().run() {
            Ok(p) => (p, ProofSystem::Groth16),
            Err(e) => {
                let msg = format!("{e:#}");
                eprintln!("groth16 prove failed ({msg}); trying compressed fallback...");
                fell_back = true;
                let p = client
                    .prove(&pk, stdin)
                    .compressed()
                    .run()
                    .expect("compressed prove also failed");
                (p, ProofSystem::Compressed)
            }
        },
        ProofSystem::Compressed => {
            let p = client
                .prove(&pk, stdin)
                .compressed()
                .run()
                .expect("compressed prove failed");
            (p, ProofSystem::Compressed)
        }
    };

    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("verify failed");

    let pv_bytes = proof.public_values.as_slice().to_vec();
    let decoded = PublicValues::abi_decode(&pv_bytes).expect("abi_decode public values");
    assert_eq!(decoded.id.as_slice(), &id, "committed id mismatch");
    assert_eq!(
        decoded.visibleResult, args.visible,
        "committed visible mismatch"
    );

    let proof_bytes = proof.bytes();
    let vkey = pk.verifying_key().bytes32();

    fs::write(out.join("proof.bin"), &proof_bytes).expect("write proof.bin");
    fs::write(out.join("vkey.txt"), format!("{vkey}\n")).expect("write vkey");
    fs::write(out.join("public_values.bin"), &pv_bytes).expect("write public_values.bin");
    proof
        .save(out.join("sp1_proof_with_pis.bin"))
        .expect("save full proof");

    // Convenience copy for contracts wiring — programVKey changes with guest/acceptance.
    let contracts_vkey = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/skeleton-vkey.txt");
    if let Some(parent) = contracts_vkey.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&contracts_vkey, format!("{vkey}\n"));

    let meta = Meta {
        proof_system: format!("{used_system:?}").to_lowercase(),
        requested_system: format!("{:?}", args.system).to_lowercase(),
        fell_back_from_groth16: fell_back,
        vkey_bytes32: vkey.to_string(),
        public_values_hex: format!("0x{}", hex::encode(&pv_bytes)),
        id_hex: format!("0x{}", hex::encode(id)),
        visible: args.visible,
        nat_expr_eval: report.nat_expr_eval,
        question_path: question_path.display().to_string(),
        answer_path: answer_path.display().to_string(),
        question_byte_len: question.len(),
        answer_byte_len: answer.len(),
        proof_byte_len: proof_bytes.len(),
        note: "NON-BECOME skeleton SP1 proof with TIER-1 CERT (bind Q/A/id) + Nat fragment (NOT full coqchk). NOT full coqchk / Rocq kernel. NOT a toy string checker. Placeholder id ≠ official jobHash. programVKey from THIS skeleton ELF only.".into(),
        docker_gap: "Docker not installed on this box; ELF built with local cargo prove / sp1-build. vkey may differ across machines until cargo prove build --docker is available.".into(),
    };
    fs::write(
        out.join("meta.json"),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .expect("write meta.json");

    println!("OK visible={} nat_expr_eval={} id=0x{}", args.visible, report.nat_expr_eval, hex::encode(id));
    println!("vkey={}", vkey);
    println!("proof_system={:?} fell_back={}", used_system, fell_back);
    println!("proof_bytes_len={}", proof_bytes.len());
    println!("public_values_hex=0x{}", hex::encode(&pv_bytes));
    println!("wrote artifacts to {}", out.display());
}


#[cfg(test)]
mod host_acceptance_tests {
    use super::check_development;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    fn fixture_dir(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../program/tests/fixtures")
            .join(name)
    }

    #[test]
    fn admitted_in_answer_fails_closed() {
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition visible_result : nat := 2.\n\
                  Definition answer : Target := ex_intro _ 2 eq_refl.\n\
                  Theorem t. Admitted.";
        let err = check_development(q, a, 2).unwrap_err();
        assert!(err.as_str().contains("forbidden"), "got: {}", err.as_str());
    }

    #[test]
    fn real_job_bytes_pass_eval_2() {
        let q = include_bytes!("../../../../jobs/yaa-1plus1-zkp/Question.v");
        let a = include_bytes!("../../../../jobs/yaa-1plus1-zkp/answer.v");
        let r = check_development(q, a, 2).expect("real job");
        assert_eq!(r.nat_expr_eval, 2);
    }

    #[test]
    fn semantic_one_plus_one_not_three() {
        let q = b"Definition Target : Prop := exists n : nat, 1 + 1 = n.";
        let a = b"Definition answer : Target := ex_intro _ 3 eq_refl.\n\
                  Definition visible_result : nat := 3.\n";
        assert!(check_development(q, a, 3).is_err());
    }

    #[test]
    fn mul_fixture_kernel_accepts() {
        let dir = fixture_dir("mul_target");
        let q = fs::read(dir.join("Question.v")).unwrap();
        let a = fs::read(dir.join("answer.v")).unwrap();
        let r = check_development(&q, &a, 6).expect("mul_target kernel");
        assert_eq!(r.nat_expr_eval, 6);
    }

    #[test]
    fn mul_wrong_visible_fails() {
        let q = b"Definition Target : Prop := exists n : nat, 2 * 3 = n.";
        let a = b"Definition answer : Target := ex_intro _ 5 eq_refl.\n\
                  Definition visible_result : nat := 5.\n";
        assert!(check_development(q, a, 5).is_err());
    }

    #[test]
    fn eq_shape_wrong_visible_fails() {
        let q = b"Definition Target : Prop := 1 + 1 = 2.";
        let a = b"Definition answer : Target := eq_refl.\n\
                  Definition visible_result : nat := 3.\n";
        assert!(check_development(q, a, 3).is_err());
    }

    /// Host: .v that coqc/coqchk accept, then assert kernel accepts too.
    #[test]
    fn mul_fixture_coqc_coqchk_then_kernel() {
        let dir = fixture_dir("mul_target");
        let coqc_q = Command::new("coqc")
            .current_dir(&dir)
            .args(["-q", "Question.v"])
            .output()
            .expect("spawn coqc");
        assert!(
            coqc_q.status.success(),
            "coqc Question.v: {}",
            String::from_utf8_lossy(&coqc_q.stderr)
        );
        let coqc_a = Command::new("coqc")
            .current_dir(&dir)
            .args(["-q", "answer.v"])
            .output()
            .expect("spawn coqc answer");
        assert!(
            coqc_a.status.success(),
            "coqc answer.v: {}",
            String::from_utf8_lossy(&coqc_a.stderr)
        );
        let chk = Command::new("coqchk")
            .current_dir(&dir)
            .args(["-silent", "-o", "answer"])
            .output()
            .expect("spawn coqchk");
        assert!(
            chk.status.success(),
            "coqchk: {}",
            String::from_utf8_lossy(&chk.stderr)
        );
        let q = fs::read(dir.join("Question.v")).unwrap();
        let a = fs::read(dir.join("answer.v")).unwrap();
        let r = check_development(&q, &a, 6).expect("kernel after coqchk");
        assert_eq!(r.nat_expr_eval, 6);
    }
}
