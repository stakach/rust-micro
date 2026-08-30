# ReactOS ACPI provider overlay

The stock x64 livecd used by this project does not implement the standard
`IOCTL_ACPI_ENUM_CHILDREN` contract and aliases distinct ACPI namespace objects when they share a
HID without `_UID`. The patch in this directory is applied to the exact livecd source commit:

```
4117217b61b97f022e441b11639ca6f2106aaa07
```

The GitHub workflow builds only `acpi.sys` with the matching `amd64`, MSVC, Debug, NT 5.2 tuple.
The checked-in binary is the boot artifact; the workflow artifact is only a reproducibility aid.
Image creation verifies its recorded SHA-256 and overwrites the stock full-tree driver after the
ReactOS tree is copied. A missing or mismatched overlay is fatal and never falls back to the stock
driver.

`manifest.txt` records the complete source, base-media, patch, canonical artifact, build-tuple, and
build-run identities. `scripts/verify_reactos_acpi_provider.sh` verifies both the patch and the
artifact before every top-level run and again after the driver is copied into the FAT image.

The provider source and binary remain covered by the ReactOS GPLv2-or-later terms. The complete
corresponding source is the pinned upstream commit plus the patch in this directory.
