# stream-capped-el9-4

F-03 fixture: makes the **at-stream-max** verdict reachable in the bash gate
tests, which it previously was not.

Only 7 of the shipped fixtures carry `clusterversion.txt` at all (six say
`4.21.0`, one `4.13.0` with no guest evidence), so `STREAM`/`STREAM_MAX` were
empty everywhere and `driver-verdict.sh`'s stream-ceiling branch never fired
under test. The scoring change it guards was therefore covered only by the
shared vectors, never end to end.

- `clusterversion.txt` = `4.18.26` -> el9_4, whose ceiling is 1.9.46
- guest `virtio_version.txt` = `1.9.46` -> exactly at the ceiling

Expected: Gate 15 emits the ceiling WARN under **gate 22** (`platform` domain,
weight 0), so the VM stays LOW rather than carrying the 4.50 that used to land
identically on every VM of a capped stream.
