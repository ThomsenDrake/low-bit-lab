# Artifact and checkpoint retention

- Git stores configs, manifests, reports, and small fixtures—not weights, datasets, checkpoints, credentials, or private prompts.
- Large blobs belong in a content-addressed cache outside Git. Manifests record hashes and provenance; paths must not expose credentials.
- `retain` is the default cleanup policy. `delete_ephemeral_only` may remove only paths explicitly created and owned by the current recorded run.
- Promoted artifacts are never deleted automatically. Unknown ownership or a hash mismatch is a stop condition.
- Phase 0 creates no model/checkpoint blobs and performs no destructive cleanup.

