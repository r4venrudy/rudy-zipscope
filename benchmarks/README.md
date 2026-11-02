# Reproducible installed-command measurement

`python benchmarks/measure.py PATH_TO_ZIPSCOPE` creates two controlled 64-entry workloads containing one MiB of decoded data each, one stored and one DEFLATE-compressed. It warms up three times, verifies report equality on every run, then reports five actual elapsed measurements with process startup included. No throughput or competitive-speed claim is implied; use recorded machine/runtime metadata when comparing runs.

The native suite separately exercises a 2,000-link acyclic graph and fixed-seed malformed byte streams. The checker memoizes link reachability and retains decoded prefixes only for declared symlink targets (up to 4 KiB), not ordinary file contents. CRC and SHA-256 scan all supported payload bytes within the configured expansion limits.
