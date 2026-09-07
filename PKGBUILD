# Maintainer: Ozan Özdil <ozdil>
pkgname=omarchy-omablock
pkgver=1.0.0
pkgrel=1
pkgdesc="Machine-Age Zero-Latency AdBlocker & Privacy Shield for Omarchy Linux"
arch=('x86_64')
url="https://github.com/ozdil/omarchy-omablock"
license=('MIT')
depends=('glibc' 'gcc-libs' 'curl' 'python')
makedepends=('cargo' 'rust')

build() {
    cd "${startdir}"
    cargo build --release --locked
}

package() {
    cd "${startdir}"
    install -Dm755 "target/release/omablock-engine" "${pkgdir}/usr/bin/omablock"
    install -Dm755 "omablock-hosts-sync" "${pkgdir}/usr/local/bin/omablock-hosts-sync"
    install -Dm755 "target/release/omablock-engine" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/omablock-engine"
    install -Dm755 "omablock-hosts-sync" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/omablock-hosts-sync"
    install -Dm644 "manifest.json" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/manifest.json"
    install -Dm644 "Panel.qml" "${pkgdir}/usr/share/omarchy/plugins/ozdil.omablock/Panel.qml"
    install -Dm644 "README.md" "${pkgdir}/usr/share/doc/${pkgname}/README.md"
    install -Dm644 "LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
