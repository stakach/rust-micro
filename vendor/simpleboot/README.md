# Simpleboot source used by the image creator

These three upstream source files come from [Simpleboot](https://gitlab.com/bztsrc/simpleboot) commit `f5fa29fe6613dc20b3729e769c68f9435daa15d1` (`src/`). Their SHA-256 values are recorded in `checksums.sha256`. Each file contains the upstream MIT license notice. `scripts/make_image.sh` verifies the unmodified sources, copies them to `.tmp/simpleboot-src`, applies `scripts/patches/simpleboot-fat-allocation.patch` to the copy, and compiles the host image creator. The published LiberNT image and binaries are unaffected.
