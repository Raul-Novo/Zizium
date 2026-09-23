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

## Documentation naming and tone

Current reference documentation identifies releases by version number and
describes behaviour by subsystem. Do not use release codenames or informal
development-stage shorthand as product documentation. State supported contracts,
verified behaviour, limitations and outstanding work directly. Do not imply
production support from an experimental acceptance test.

Keep exact API names, paths, command arguments, artefact names and diagnostic
markers unchanged when quoting technical interfaces. Historical verification
reports retain their original terminology as evidence; new reports use current
version and subsystem names. The internal roadmap retains numbered work items
for dependency tracking, not as release branding.

## Implemented

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
