# opam-mirror unikernel

This unikernel periodically (at startup, on request, every hour) updates the
provided opam-repository and downloads all referenced archives. It acts as
an opam-repository including archive mirror. Only archives with appropriate
checksums are stored.
