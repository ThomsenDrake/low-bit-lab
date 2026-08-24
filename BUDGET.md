# Budget Policy

The public scaffold authorizes USD 0 of cloud spend.

`configs/budget-policy.json` and `src/lowbit_lab/constants.py` independently freeze the total, automated ceiling, reserve, single-job cap, price input, and every phase cap at zero. The remote dry run records a zero-cost plan and cannot submit it.

A future positive budget requires explicit human approval, a target-specific controlling plan, matching changes to both policy representations, focused guard tests, and a report-only safety review. Credentials and billing details must not be committed.

The public no-weight provider-smoke adapter does not change these zero defaults. Any future smoke
execution requires a validated ignored ledger, a separate exact action approval, and an atomic local
USD 4.00 reservation. That reservation is a local stop control, not a provider-enforced dollar cap;
the approval must explicitly accept residual provider-managed execution risk. Code presence and a
total ledger ceiling are not spend authority.
