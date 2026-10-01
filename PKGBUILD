# Maintainer: Ozan Özdil <ozdil>
pkgname=omarchy-omablock
pkgver=1.3.0
pkgrel=1
pkgdesc="Machine-Age Zero-Latency AdBlocker & Privacy Shield for Omarchy Linux"
arch=('x86_64')
url="https://github.com/ozdil/omarchy-omablock"
license=('MIT')
depends=('glibc' 'gcc-libs' 'curl' 'python' 'polkit' 'quickshell')
makedepends=('cargo' 'rust')

build() {
    cd "${startdir}"
    cargo build --release --locked
}

package() {
    cd "${startdir}"
    # Standard executables
    install -Dm755 "target/release/omablock-engine" "${pkgdir}/usr/bin/omablock"
    install -Dm755 "target/release/omablock-engine" "${pkgdir}/usr/bin/omablock-engine"
    install -Dm755 "omablock-hosts-sync" "${pkgdir}/usr/bin/omablock-hosts-sync"
    install -Dm755 "omablock-dashboard" "${pkgdir}/usr/bin/omablock-dashboard"
    install -Dm755 "omablock-status" "${pkgdir}/usr/bin/omablock-status"

    # Polkit authorization action and desktop entry
    install -Dm644 "assets/io.omarchy.omablock.policy" "${pkgdir}/usr/share/polkit-1/actions/io.omarchy.omablock.policy"
    install -Dm644 "omablock.desktop" "${pkgdir}/usr/share/applications/omablock.desktop"

    # Omarchy plugin directory
    install -d "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock"
    install -Dm755 "target/release/omablock-engine" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/omablock-engine"
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
    install -Dm644 "LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
