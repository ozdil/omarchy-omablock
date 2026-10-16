# Maintainer: Ozan Özdil <ozdil>
pkgname=omarchy-omablock
pkgver=1.5.1
pkgrel=1
pkgdesc="Machine-Age Zero-Latency AdBlocker & Privacy Shield for Omarchy Linux"
arch=('x86_64')
url="https://github.com/ozdil/omarchy-omablock"
license=('MIT')
depends=('glibc' 'gcc-libs' 'curl' 'python' 'polkit' 'quickshell')
optdepends=('nftables: kernel-level DoH/DoT enforcement')
makedepends=('cargo' 'rust')
install=omablock.install

_rust_host() {
    rustc -vV | sed -n 's/host: //p'
}

# Build into a directory we own with an explicit --target, so a user-level
# CARGO_TARGET_DIR or a build.target / build.target-dir setting in
# ~/.cargo/config.toml cannot move the binary somewhere package() won't look.
_bin() {
    echo "${srcdir}/cargo-target/$(_rust_host)/release/omablock-engine"
}

prepare() {
    cd "${startdir}"
    # Fetch crates up front so build() works offline and with --frozen
    cargo fetch --locked --target "$(_rust_host)"
}

build() {
    cd "${startdir}"
    cargo build --release --frozen --target "$(_rust_host)" --target-dir "${srcdir}/cargo-target"
}

package() {
    cd "${startdir}"
    local bin
    bin="$(_bin)"
    # Standard executables
    install -Dm755 "${bin}" "${pkgdir}/usr/bin/omablock"
    install -Dm755 "${bin}" "${pkgdir}/usr/bin/omablock-engine"
    install -Dm755 "omablock-hosts-sync" "${pkgdir}/usr/bin/omablock-hosts-sync"
    install -Dm755 "omablock-dashboard" "${pkgdir}/usr/bin/omablock-dashboard"
    install -Dm755 "omablock-status" "${pkgdir}/usr/bin/omablock-status"

    # Polkit authorization action and desktop entry
    install -Dm644 "assets/io.omarchy.omablock.policy" "${pkgdir}/usr/share/polkit-1/actions/io.omarchy.omablock.policy"
    install -Dm644 "omablock.desktop" "${pkgdir}/usr/share/applications/omablock.desktop"

    # Omarchy plugin directory
    install -d "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock"
    install -Dm755 "${bin}" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/omablock-engine"
    install -Dm755 "omablock-hosts-sync" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/omablock-hosts-sync"
    install -Dm755 "omablock-dashboard" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/omablock-dashboard"
    install -Dm755 "omablock-status" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/omablock-status"
    install -Dm644 "manifest.json" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/manifest.json"
    install -Dm644 "Panel.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/Panel.qml"

    install -d "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/qml"
    cp -r qml/* "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/qml/"

    # Omarchy Chromium Browser Extension
    install -d "${pkgdir}/usr/share/omarchy/default/chromium/extensions/omablock"
    cp -r extensions/chrome/* "${pkgdir}/usr/share/omarchy/default/chromium/extensions/omablock/"

    install -Dm644 "README.md" "${pkgdir}/usr/share/doc/${pkgname}/README.md"
    install -Dm644 "CHANGELOG.md" "${pkgdir}/usr/share/doc/${pkgname}/CHANGELOG.md"
    install -Dm644 "LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
