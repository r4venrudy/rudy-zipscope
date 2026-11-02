# Invented archive corpus

`python examples/make_archives.py artifacts/synthetic` creates a new directory of deterministic ZIP files and `expected.json`. Members are invented data; the generator never extracts or executes them. Traversal/link names exist only as archive metadata. The manifest records expected profile findings/stops and Python `zipfile` decoded-content/hash oracles for supported coherent archives.

Compare `stored.zip` and `deflated.zip`: file content, names and attributes match even though compression bytes differ. `changed.zip` modifies a payload. `local-disagreement.zip` changes one local name while retaining the central name. `ambiguous-footer.zip` embeds an exact-ending EOCD decoy in an outer comment; ZipScope refuses to select one reader interpretation. `unicode-override.zip` has a valid CRC-qualified Unicode alternative name containing parent traversal.

Run `zipscope inspect ARCHIVE --format html --output NEW_REPORT.html` for a local investigation. Findings are conservative profile observations, not evidence that a particular extractor is exploitable. Releases contain the generated corpus; source checkouts create it on demand.
