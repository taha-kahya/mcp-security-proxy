# Unicode 17.0.0 data for Scan

Vendored without changes from the Unicode Consortium, under the Unicode
License v3 (`LICENSE.txt`). Scan's lookalike detection uses them; see
`services/scan/unicode_data.py`.

| File | Source | SHA-256 |
| --- | --- | --- |
| `confusables.txt` | <https://www.unicode.org/Public/17.0.0/security/confusables.txt> (UTS #39) | `091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a` |
| `Scripts.txt` | <https://www.unicode.org/Public/17.0.0/ucd/Scripts.txt> | `9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf` |
| `LICENSE.txt` | <https://www.unicode.org/license.txt> | `e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96` |

`tests/contracts/test_scan_unicode_data.py` pins these hashes, so the files
can't change by accident.

## Updating to a new Unicode version

1. Download the two data files and the license for the new version from the
   URLs above (replace `17.0.0`) into a new `unicode-<version>/` folder,
   next to a copy of this README.
2. Update the hashes in this README and in the test.
3. Change `UNICODE_VERSION` in `services/scan/unicode_data.py`. It is part
   of Scan's version, so cached scan results are invalidated.
4. Delete the old folder and run the test suite.

Both files must come from the same Unicode version. Python's own
`unicodedata` (used for normalization) follows the interpreter's Unicode
version; a difference of one or two versions doesn't affect detection.
