(* Fixture: exists-shape Target with 2*3 — coqc/coqchk accept; kernel must too. *)
Require Import Coq.Arith.PeanoNat.

Definition Target : Prop := exists n : nat, 2 * 3 = n.
