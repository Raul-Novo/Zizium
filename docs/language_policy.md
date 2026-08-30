# British-English policy

All Zizium-owned English in documentation, source comments, diagnostics,
configuration, user-visible text, and natural identifiers uses British
spelling. Examples include `colour`, `behaviour`, `initialise`, `serialise`,
`normalise`, `synchronise`, `programme`, `licence`, `centre`, `favour`,
`neighbour`, `catalogue`, and `dialogue`.

External spellings remain exact when required by PE/COFF, CPU manuals,
third-party headers, command-line flags, Windows SDK contracts, paths such as
`C:\Program Files`, SPDX tags, or other compatibility surfaces. A required
external identifier is never renamed merely for spelling.

## Implemented in Seed

`scripts/check_spelling.py` scans project-owned text and source for a focused
set of forbidden alternatives. It excludes fetched dependencies, build output,
the pre-existing style guide, the formal licence text, required external paths,
URLs, and SPDX tags.

## Scaffolded

The current list catches high-risk words from the project mandate. It is not a
general grammar checker.

## Future

The list should grow only with reviewed, low-false-positive rules. Generated
and translated content needs separate policy.
