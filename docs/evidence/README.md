# Evidence index

Evidence хранит manifest, preflight, host/guest snapshots, reports и hashes.
Verifier принимает только output-local regular files, полные mandatory records и
согласованные SHA-256. Неполный bundle получает `BLOCKED`.
