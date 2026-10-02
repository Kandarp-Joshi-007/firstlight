# Seed

`irish-candidates.txt` holds the Irish-brand candidates found by `brands.py`
when run over a public corpus of 391,986 known-phishing domains
(mitchellkrogza/Phishing.Database). They are already on public blocklists;
nothing here is newly disclosed.

They exist for two reasons. They validate the pipeline end to end on domains
whose label is known, and they give the dashboard something real to show while
live detections accumulate - Irish-brand impersonation appears roughly once per
60,000 domain names observed, so a cold start is sparse for a long time.

Rows scored from this file are stored with source `backfill:phishdb` and are
tagged `corpus` on the dashboard, so they are never mistaken for live sightings.
