# Sanitized topology failures — requirements brainstorm

## Problem

The final pre-reservation topology refresh stopped correctly, but the observer collapsed every
network and policy failure into one generic message. Because no URL or redirect material may be
retained, the existing evidence cannot distinguish a transient connection failure from DNS, peer,
redirect, URL-policy, or HTTP-status drift.

## Requirements

- Preserve only a closed, target-neutral failure code already produced by the reviewed transport
  walker, plus a numeric artifact ordinal.
- Convert raw connection failures to one fixed `network_failure` code without exception chaining.
- Never expose or persist a URL, host, path, query, header, address, cookie, credential, or response
  body.
- Keep the observation HEAD-only, proxy-free, single-attempt, and body-free.
- Do not reserve budget, contact Modal, transfer weights, or weaken any transport rule.
- Cover secret non-retention and unknown-exception collapse with focused tests.

## Success state

A future zero-spend topology observation can identify the failed invariant safely enough to decide
whether U8 may proceed, while all unreviewed exception content remains erased.
