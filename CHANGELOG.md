# Changelog

## 1.5.0

### Fixed

- Kernel rules: the `inet omablock` and `inet omablock_blackout` nftables tables are now written correctly and applied through the privileged helper.
- Ultimate mode filters categories like Aggressive mode. DoH blocking honours the `doh_prevention` setting and never blocks a whitelisted DoH domain.
- `/etc/hosts` sync keeps the file's mode and owner, writes atomically, and serialises concurrent privileged runs.
- Every rule, built-in or downloaded, is validated as a domain before it reaches `/etc/hosts`. Invalid entries are skipped and counted.
- Status counts come from the managed hosts block itself, so the panel shows the real number of active rules.
- The IDN homograph alert clears when its domain is removed from the whitelist.
- Restoring the hosts backup turns the shield off, so the next sync does not undo the restore.
- The engine no longer logs owner UIDs when `config.json` is unreadable.
- An unreadable `config.json` (wrong owner, too large, not UTF-8) is never overwritten with defaults; changes are refused until it is fixed.
- `--startup` applies the saved settings under the config lock, so turning protection off while it starts is not undone.
- `uninstall.sh` also lifts an active panic blackout, so DNS is not left blocked.
- The active rule count is correct even when `/etc/hosts` contains non-UTF-8 bytes.
- The look-alike domain alert stays on while any flagged domain is still whitelisted.
- The Chrome extension's service worker applies whitelist changes, so closing the popup mid-toggle cannot leave a site blocked.
- PKGBUILD builds into its own target directory, so a custom `CARGO_TARGET_DIR` or `~/.cargo/config.toml` no longer breaks `makepkg`.

### Added

- `omablock --restore-hosts` restores `/etc/hosts` from the backup taken before the first sync.
- Pause now ends on its own: a `systemd-run --user` timer runs `omablock --expire-pause` when the pause expires.
- Clear exit codes: `0` OK, `1` sync failed, `2` invalid input, `3` integrity unknown, `4` system helper not installed. The panel shows a matching message for each.
- The Chrome / Chromium extension (1.0.6) has an English and Turkish UI, a per-tab badge, no ad flash on load, and no longer needs the `tabs` permission.
- A shared QML client queues engine actions in order, so quick clicks no longer get lost.
- CI runs Rust tests, a full privileged end-to-end test in isolated namespaces, and QML runtime tests under Qt 6.

### Changed

- CI actions are pinned to commit hashes.

- The README describes what each feature actually does: NSS resolution in user space, polkit asking once per session, and USB armor marked experimental.
