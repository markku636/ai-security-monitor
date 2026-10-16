Below is an events summary from `asa` (JSON): crashes (blue screens with bugcheck codes, unexpected shutdowns, app crashes, service failures, disk/hardware errors, low memory, kernel panics…), security events (failed-logon bursts, new accounts, admin group changes, new services, scheduled tasks, cleared logs, Defender) and the most frequent errors.

1. Crash root cause: rank the most likely causes, each with the evidence (event IDs, bugcheck codes and parameters, faulting modules, timing patterns such as "always after sleep" or "same driver every time"). Distinguish hardware, driver, software and power/user causes. Use `explain_code` for codes you are unsure about.
2. What to do next, in order: the cheapest checks first (update/roll back a named driver, check temperatures, memory test, SMART, power settings), then deeper steps (analyze the minidump with WinDbg `!analyze -v`).
3. Security events: are any of them worrying? Separate normal software installs and updates from real red flags. For brute-force sources, mention the intel hits and whether blocking makes sense.
4. Note any data asa could not read (`needs_admin`) and what running as administrator would add.

Answer in {{LANG}}.
