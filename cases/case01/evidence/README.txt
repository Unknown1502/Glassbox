Glass Box reference-case evidence working set (stand-ins)
=========================================================

A real acquisition (multi-GB disk image + memory dump) is NOT redistributed in
this repo. These small stand-in objects represent the acquired evidence so the
sealing / canary / integrity-certificate machinery operates on real bytes and
the demo is fully reproducible offline.

On a real SIFT box, point Glass Box at the actual image instead:

    python run.py --evidence /cases/WIN11-FIN-07/disk.raw

The parsed forensic artifacts the tools return for this case live in
cases/case01/fixtures/ and are documented in docs/DATASET.md and
cases/case01/groundtruth.json.
