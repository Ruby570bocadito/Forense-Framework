# Test data

| File | Source | License |
|---|---|---|
| `new-user-security.evtx`, `Security_short_selected.evtx` | [omerbenamram/evtx](https://github.com/omerbenamram/evtx) `samples/` | MIT / Apache-2.0 |
| `prefetch/*.pf` (Windows XP, 7 and 10 formats) | [log2timeline/plaso](https://github.com/log2timeline/plaso) `test_data/winprefetch/` | Apache-2.0 ([LICENSE-plaso.txt](LICENSE-plaso.txt)) |
| `jumplists/*.automaticDestinations-ms`, `jumplists/*.customDestinations-ms` | plaso `test_data/` | Apache-2.0 |
| `SRUDB.dat.gz` (gzip of `SRUDB.dat`) | plaso `test_data/` | Apache-2.0 |
| `image.E01` | plaso `test_data/` | Apache-2.0 |
| `vss.raw.gz`, `ntfs-differential.vhdx.gz`, `ntfs-parent.vhdx.gz`, `ext2.vmdk.gz`, `windows_volume.qcow2.gz` (gzip of the originals) | [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) `test_data/` | Apache-2.0 |
| `ads.ntfs.gz` | Generated for this project: NTFS volume (mkntfs + ntfs-3g) with alternate data streams, one of them sparse | Same as the project |
| `ntfs.E01` | Generated for this project: 24 MiB NTFS volume (mkntfs + ntfs-3g) holding the demo Windows artifacts, acquired with `ewfacquire` | Same as the project |

Every other artifact used by the tests (registry hives, LNK, `$I`, `$MFT`,
browser databases, Prefetch v23, ShellBags, images) is generated on the fly
by `forense.demo.builders`.

The BitLocker test runs only when `FORENSE_TEST_DATA` points to a dfvfs `test_data`
checkout (its `bdetogo.raw` is 64 MiB and does not compress).
