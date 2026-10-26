# Provenance and release status

Original project code was developed for a private Discord/AMP installation and
extracted into this generic alpha under the owner's direction. Original source
is licensed Apache-2.0 with copyright identity gdragon-git. The current candidate
reuses the existing coordinator, journals, narrow AMP API, guard/observer logic
and synthetic tests; deployment identities and private administrative tooling
are excluded. Provider/library prototype code is not silently incorporated.

This candidate adds explicit configuration, profile-bound transport/state,
configured UDP WOL, local diagnostics/rendering and package metadata. Private
live-use results apply to the previous deployment, not automatically to these
changes. The owner's decision defers independent installation proof and permits
preparation of an experimental source release with these limits stated.

No AMP/game binaries, credentials, household profiles, admin keys/pins, journals,
backups, raw private evidence or private workspace history belong in an export.
Third-party code is installed externally; its evaluated dependency license/notice
texts are retained in THIRD_PARTY_LICENSES with declarations in THIRD_PARTY.md.
The exact selected source/artifacts still receive a final owner publication review.
No repository upload or hosted CI run is implied by local preparation.
