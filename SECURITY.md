# Security and disclosure

ZipScope reads bounded local ZIP bytes and never extracts, executes or follows archive members. It has no network client, dynamic model loading, target access or telemetry. Use stable authorized copies. Preview conclusions apply only to the documented profile; a policy finding is not a confirmed vulnerability in any named extractor.

Budgets cover input bytes, entry count, per-entry/total expanded bytes, retained link text, namespace component work and report output. They reduce resource abuse; they are not a hard process-memory or wall-time sandbox. Ordinary payload bytes are streamed into CRC/SHA and not retained; declared link targets retain up to 4 KiB. The CLI bounds input before allocation and rechecks the same opened file after analysis, without guaranteeing an atomic snapshot against hostile change/restore or path replacement.

Default reports omit names and payload/link-target values. Hashes, offsets, sizes and shape can still reveal identifying information. `--show-names` explicitly discloses path names (or exact raw hex for invalid encoding). Source ZIPs and synthetic corpora contain their original member bytes. Do not attach real sensitive archives to public reports.

Report creation is exclusive. POSIX requests owner-only permissions; Windows inherits the destination directory's permissions. An I/O failure may leave a partial newly created file. CRC verifies accidental/corrupt-content consistency, not publisher identity; SHA-256 is an evidence identity, not signature authentication.

For sensitive vulnerabilities, contact the repository owner privately with source version, bounded synthetic reproduction, declared profile, expected behavior and observed evidence. No production support, certification, universal extractor coverage or malware-detection claim is made for this preview.
