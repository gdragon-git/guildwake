# Testing and proof limits

Run `python -B tools/test.py` from an environment with the pinned Discord extra.
It selects synthetic profiles and owned fixtures, constrains parent-process test
sockets to loopback and prints counts/skips. It is test instrumentation, not an
OS sandbox. It logs into no Discord app and uses no real AMP or wake target.

Retained tests cover authorization, private Discord/cache behavior, journals,
idempotence, cooldown/serialization, status cancellation/recovery, AMP session
refresh, maintenance/other-game/unknown refusal, guard process turnover and
conservative blocked/uncertain receipts. Added tests exercise strict immutable
profiles, another synthetic installation through actual policy/AMP/Discord choice
construction, configured WOL packet assembly, mismatched profile denial, inactive
rendering and metadata-only diagnostics. Dangerous effects are substituted.

Linux peer/process/root-identity cases skip on Windows and must be reported as
skipped. The CI workflow proposes portable and Linux fixture jobs and package
checks. Merely supplying a workflow is not a recorded hosted CI run. No clean
systemd installation, independent operator setup, ARM packaging or actual live
wake/start of this configurable alpha is qualified. Those are deferred by the
owner; publishing an experimental source alpha must retain these explicit limits.

`tools/package_check.py --output NEW_DIRECTORY` builds wheel/sdist with existing
setuptools/wheel, inspects the exact payload and checks the safe CLI from an
isolated unpacked wheel. It downloads nothing and installs/starts no host service.
It refuses overwriting results. A local artifact smoke test is not a clean Linux
installation or proof of another user's environment.
