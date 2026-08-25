# Budget Policy

The public scaffold authorizes USD 0 of cloud spend.

`configs/budget-policy.json` and `src/lowbit_lab/constants.py` independently freeze the total, automated ceiling, reserve, single-job cap, price input, and every phase cap at zero. The remote dry run records a zero-cost plan and cannot submit it.

A future positive budget requires explicit human approval, a target-specific controlling plan, matching changes to both policy representations, focused guard tests, and a report-only safety review. Credentials and billing details must not be committed.

The public no-weight provider-smoke adapter does not change these zero defaults. Any future smoke
execution requires a validated ignored ledger and campaign authority plus an atomic local
reservation no larger than confirmed unspent campaign balance. The campaign has one cumulative
lifetime USD 4.00 ceiling. Active and audit-blocked attempts retain requested cost; settled or
failed attempts consume authoritative actual cost. These are local stop controls, not a
provider-enforced dollar cap. Code presence and a total ledger ceiling are not spend authority.
