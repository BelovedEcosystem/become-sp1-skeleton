(* Negative: claims visible 5 for 2*3 — kernel must reject (coqc may still typecheck). *)
Require Import Question.
Definition answer : Target := ex_intro _ 5 eq_refl.
Definition visible_result : nat := 5.
