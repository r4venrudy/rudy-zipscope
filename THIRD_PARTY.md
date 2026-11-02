# Third-party sources

zlib 1.3.2 provides bounded raw-DEFLATE decoding and CRC-32. The selected unmodified source files come from https://zlib.net/zlib132.zip; the official archive SHA-256 is `e8bf55f3017aa181690990cb58a994e77885da140609fc8f94abe9b65d2cae28`. See third_party/zlib/LICENSE. No gzip/file-extraction API is linked.

nlohmann/json 3.12.0 is the vendored single-header JSON serializer, under MIT; see third_party/nlohmann/LICENSE.MIT. Both dependencies are compiled from bundled sources, without package-registry access.
