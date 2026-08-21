# Budget Policy

The public scaffold authorizes USD 0 of cloud spend.

`configs/budget-policy.json` and `src/lowbit_lab/constants.py` independently freeze the total, automated ceiling, reserve, single-job cap, price input, and every phase cap at zero. The remote dry run records a zero-cost plan and cannot submit it.

A future positive budget requires explicit human approval, a target-specific controlling plan, matching changes to both policy representations, focused guard tests, and a report-only safety review. Credentials and billing details must not be committed.

