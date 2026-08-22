# Modal boundary

`job_wrapper.py` remains plan-only and has no submission code path. `reference_job.py` exposes the
reviewed A100-80GB resource declaration as data, not as a `modal.App` or remote function. The Modal
SDK is version-locked in the `remote` dependency group for reproducibility, but production code does
not import it and no command in this repository can submit the declaration.

Reference previews require exact local plan, inventory, runtime, evaluation, and budget identities.
They record `submit:false`, zero requested/actual cost, no uploads, no mounts, no volumes, no secrets,
and all unresolved execution blockers. U8 must add a separately reviewed adapter before any provider
call can exist.
