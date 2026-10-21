# Knowledge data contracts

The five referenced knowledge catalogs declare `SCHEMA_VERSION = 1` in their
existing Python data modules. Query loaders reject missing, boolean or unsupported
versions instead of interpreting incompatible data silently. Their lookup/search
results and catalog content retain the existing shape.

Run the offline validation gate before changing or publishing catalog data:

```sh
python -m moonmcp.knowledge.validation
```

It prints a JSON report and exits with status 0 only when all five catalogs pass.
It validates every named collection, required field types, nonempty IDs/names/
summaries, duplicate IDs, structured injection payloads and signatures, regex
compilation, severity/popularity labels, and vulnerability-to-root-cause foreign
keys. It never executes payloads, fetches links or contacts an assessed target.

For focused tooling, use `validate_catalog(name, namespace=None)` and
`validate_all()` from `moonmcp.knowledge.validation`. Catalog names are
`injections`, `techniques`, `vulns`, `privesc` and `waf`. An explicit namespace
lets a maintainer validate edited data before replacing the installed module.

Version 1 permits additional optional fields. It preserves the concise historical
vulnerability entries that omit severity/tools and express detection as one
string, while the longer entries use a list. `derived_vuln_classes` in the
root-cause catalog contains descriptive labels rather than vulnerability IDs;
the actual foreign key is `SERVER_SIDE_VULNS.root_cause`.

This delivers roadmap KB1/KB5/KB11/KB15 schema versioning and adds shared validation
for the integrity portion of KB2/KB6/KB10/KB12. The KB8 typo and KB9 foreign-key
guard were already present. Python storage is retained; moving the data to
external JSON/YAML remains separate work. Passing schema validation establishes
data consistency, not the truth of reference text, payload efficacy or resistance
to regex resource exhaustion.
