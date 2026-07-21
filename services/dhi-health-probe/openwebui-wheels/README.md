# Open WebUI security wheels

These wheels update four packages in the pinned Open WebUI base image. The
updates close known high-severity findings without giving the Docker build
network access.

The files came from the Python Package Index (`files.pythonhosted.org`). The
`SHA256SUMS` file pins every byte. The Docker build checks those hashes before
it installs a wheel and fails if a file changes.

There are separate compiled wheels for `amd64` and `arm64`. The pure Python
wheels under `any` work on both platforms. To refresh them, download the exact
reviewed versions for both platforms, update `SHA256SUMS`, run the image tests,
and review the final-image vulnerability report before committing.
