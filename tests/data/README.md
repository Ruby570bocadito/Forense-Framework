# Test data

| File | Source | License |
|---|---|---|
| `new-user-security.evtx`, `Security_short_selected.evtx` | [omerbenamram/evtx](https://github.com/omerbenamram/evtx) `samples/` | MIT / Apache-2.0 |
| `prefetch/*.pf` (Windows XP, 7 and 10 formats) | [log2timeline/plaso](https://github.com/log2timeline/plaso) `test_data/winprefetch/` | Apache-2.0 ([LICENSE-plaso.txt](LICENSE-plaso.txt)) |
| `jumplists/*.automaticDestinations-ms`, `jumplists/*.customDestinations-ms` | plaso `test_data/` | Apache-2.0 |
| `SRUDB.dat.gz` (gzip of `SRUDB.dat`) | plaso `test_data/` | Apache-2.0 |
| `image.E01` | plaso `test_data/` | Apache-2.0 |
| `ntfs.E01` | Generated for this project: 24 MiB NTFS volume (mkntfs + ntfs-3g) holding the demo Windows artifacts, acquired with `ewfacquire` | Same as the project |

Every other artifact used by the tests (registry hives, LNK, `$I`, `$MFT`,
browser databases, Prefetch v23, ShellBags, images) is generated on the fly
by `forense.demo.builders`.
