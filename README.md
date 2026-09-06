# become-sp1-skeleton (NON-BECOME / TEST_ONLY)

SP1 guest skeleton for Beloved Ecosystem / BECOME interim settlement.

## Docker-reproducible ELF

```bash
cd program
cargo prove build --docker --tag v6.6.0
```

CI: `.github/workflows/docker-elf.yml` (`workflow_dispatch` + push to `main`).

Local builds without Docker are fine for toys — do **not** claim a Docker freeze from a local-only ELF.

## Labels

- Guest is an **acceptance kernel fragment**, not full `coqchk`
- `programVKey` changes when the guest ELF changes
- Official BECOME guest / founder pins are separate
