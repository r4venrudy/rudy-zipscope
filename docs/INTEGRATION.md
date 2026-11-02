# Embed the native core

`zipscope_core` is a C++20 CMake target; it links the bundled raw-DEFLATE/CRC implementation. The built `zipscope_embed` example analyzes an in-memory empty ZIP and exports evidence. No input can load plugins or invoke an extractor.

```cpp
#include "zipscope/parser.hpp"
#include "zipscope/compare.hpp"
#include "zipscope/output.hpp"

auto report = zs::analyze(bytes, zs::Limits{});
if (!report.complete) {
    // Treat stop_code/stop_offset as an incomplete result, never as clear.
}
auto evidence = zs::json(report); // names omitted by default
```

Input bytes must remain stable for the duration of `analyze`. The result owns its metadata and retains at most 4 KiB per symlink target, not ordinary decoded payloads. The CLI uses `Snapshot` to bound and recheck the same opened file; this is not an atomic filesystem snapshot or hostile-writer guarantee. Caller-created reports are trusted in-process structures; comparison is not an importer for untrusted report JSON.

`compare` compares supported, verified, unambiguous manifests keyed by exact central-name bytes. Its projection includes decoded SHA-256, decoded size, external attributes and creator host. Compression representation, timestamps, comments and unrelated extra metadata are excluded. Whole-archive SHA-256 remains available to distinguish those bytes. Existing error-level namespace findings or incomplete inputs make comparison unavailable.

The ZIP profile is conservative. UTF-8 alternatives from a valid Info-ZIP Unicode path field are checked even when the ordinary ASCII name has no UTF-8 flag. Full CP437, Unicode case folding/NFC equivalence, filesystem mounts and specific extractor quirks are not simulated.
