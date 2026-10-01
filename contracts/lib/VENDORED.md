# Vendored dependencies

`forge-std` (≈ v1.16.x) and `openzeppelin-contracts` (≈ v5.6.x) are committed here as the exact
byte-for-byte snapshot the contract test suite was run against at retirement. They are not git
submodules on purpose: the copies do not match any single upstream release tag exactly, and this
archive keeps what was actually tested rather than a re-resolved upstream version.

Their own licenses apply (MIT / Apache-2.0, see each folder). Do not treat them as current.
