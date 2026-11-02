# Contributing

Start with a small invented archive that demonstrates a contract violation. Preserve central/local offsets, name bytes, flags, size/CRC values and the expected qualified result. Never extract a traversal/link fixture as part of a test. Do not submit another party's real archives or credentials.

Build with `-DZIPSCOPE_REQUIRE_CLI_TESTS=ON`; run CTest, including the native suite, embedded example, independent Python binary oracle and installed-command contracts. For core bounds/decoder/namespace changes also run the Linux ASan/UBSan configuration. Mutations are bounded robustness exercises, not exhaustive proof.

Keep the native model and serializer separate from file access and gates. A partial/unsupported result must never become a clear comparison or SARIF execution. Add independently reasoned Python byte/hash/metadata oracles when format support expands. Unknown metadata conventions must retain explicit scope boundaries rather than silently broaden claims.

Format authored `.cpp` and `.hpp` files with the bundled `.clang-format` convention; leave third-party sources unmodified. Update pinned dependency provenance and notices together. Source builds must remain offline and package-registry independent. Preserve RUDY README/report styling and accurate claims.
