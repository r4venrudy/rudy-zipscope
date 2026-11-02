# Rudy ZipScope v0.1.0-preview

Native C++20 offline ZIP investigations with reconciled central/local records, ZIP64, streaming descriptors, bounded stored/raw-DEFLATE verification, CRC-32/SHA-256 identities, qualified manifest differences and portable namespace observations. Includes private-by-default JSON/text/SARIF, static RUDY HTML, a native embedding example, deterministic synthetic fixtures and independent binary/command tests.

## Native packages

- `zipscope-0.1.0-preview-windows-x64.zip`: native Windows x64 command, built with the static MSVC runtime.
- `zipscope-0.1.0-preview-linux-x64.tar.gz`: native Linux x64 command, built on Ubuntu 24.04; use a compatible libc/C++ runtime environment.
- `zipscope-0.1.0-preview-macos-arm64.tar.gz`: native Apple Silicon command built on macOS 15; not Apple-signed/notarized.
- `SHA256SUMS.txt`: SHA-256 digests for the three packages. Digests detect mismatches, not independent publisher identity.

Verify downloads with `sha256sum -c SHA256SUMS.txt` or PowerShell `Get-FileHash -Algorithm SHA256`, then extract the outer native package. Run `bin/zipscope --version` or `bin\zipscope.exe --version`. The command needs no Python, language SDK, account or network service. Python is optional for source tests, generators and benchmarks.

Packages include the deterministic invented ZIP corpus under `examples/synthetic`, an expected manifest, verified inspection/comparison JSON, a disagreement investigation HTML and traversal SARIF. Inner adversarial ZIP fixtures remain files; **do not extract them as an installation step**. The C++ embedding example requires a source checkout/build. Both dependency licenses are included under `licenses/`.

Release publication depends on successful native/sanitizer verification and installed-layout checks. Immutable official Action pins, read-only defaults and a publication-only write permission are used. No existing project release tags/assets are rewritten by this new publication.

Developer preview: conservative profile observations, no universal extractor or exploitability claim. Unsupported/ambiguous/over-budget inputs remain incomplete, and incomplete or error-bearing namespaces cannot pass a manifest comparison. No network probing, payload execution, extraction or malware classification is implemented.
