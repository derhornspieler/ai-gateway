# Runtime security wheels

These wheels fix reviewed runtime vulnerabilities without giving a Docker
build network access. `SHA256SUMS` pins every byte used by the build.

- `pyasn1` 0.6.4 fixes three denial-of-service flaws in ASN.1 decoders.
- `GitPython` 3.1.54 contains the current security fixes used by Open WebUI.

Download replacement files only from PyPI during a reviewed image update.
Verify their hashes, update `SHA256SUMS`, and run the exact offline-seed
PreProd test before release.
