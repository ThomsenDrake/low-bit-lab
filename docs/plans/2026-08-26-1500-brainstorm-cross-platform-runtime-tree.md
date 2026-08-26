# Cross-platform runtime-tree identity — requirements brainstorm

## Problem

Windows and WSL must verify one immutable repository-local runtime tree. Four deeply nested public
package-license files exceed the legacy Windows path limit: Windows enumeration finds their paths
but `Path.is_file()` returns false, while WSL includes them. The Windows-created receipt therefore
omits real files and cannot reproduce under the required WSL watchdog.

## Requirements

- Hash every regular package-tree file on both Windows and WSL, including paths longer than 260
  characters.
- Preserve symlink rejection, repository confinement, relative-path identity, byte size, and
  content SHA-256 semantics.
- Regenerate the ignored receipt only after the implementation merges; do not hand-edit evidence.
- Require Windows and WSL to reproduce one identical complete-tree receipt before U8.
- Keep all provider, budget, privacy, and one-shot gates unchanged.

## Success state

Both hosts bind the same 22,259-file runtime tree and emit the same U8 request without provider
contact, reservation, or weight transfer.
