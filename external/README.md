# External dependencies

`dependencies.json` is the source of truth for versions, source URLs, hashes,
and licences. `scripts/fetch_deps.ps1` downloads verified files into
`external/deps`; that directory is intentionally ignored by version control.

No dependency is downloaded as part of an ordinary build. A missing dependency
causes a clear error that names the explicit fetch command.
