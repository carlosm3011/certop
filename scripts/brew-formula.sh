#!/usr/bin/env bash
#
# Genera la formula de Homebrew para un tag ya publicado, con el sha256 del
# tarball que GitHub sirve para ese tag.
#
#   scripts/brew-formula.sh v1.3.0
#
# La salida va a stdout: se pega en Formula/certop.rb del tap
# (github.com/carlosm3011/homebrew-certop). El tag tiene que existir y estar
# pusheado a GitHub antes de correr esto, porque el hash sale de descargarlo.
#
# La formula compila desde la fuente a proposito: asi anda igual en Apple
# Silicon y en Mac Intel — el proyecto solo publica binario darwin/arm64 — y el
# resultado nunca pasa por Gatekeeper, que es lo que evita el aviso de
# "desarrollador desconocido" del binario suelto (FUT-8).
#
set -euo pipefail

die() { printf 'brew-formula: %s\n' "$*" >&2; exit 1; }

TAG="${1:?falta el tag, por ejemplo v1.3.0}"
[ "${TAG#v}" != "$TAG" ] || TAG="v${TAG}"

printf '%s' "${TAG#v}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$' ||
	die "'${TAG}' no es semver de tres numeros (ej. v1.3.0)"

URL="https://github.com/carlosm3011/certop/archive/refs/tags/${TAG}.tar.gz"

# --fail para que un 404 no termine hasheando una pagina de error de GitHub.
SHA=$(curl -fsSL "$URL" | shasum -a 256 | cut -d' ' -f1) ||
	die "no pude bajar ${URL}: revisa que el tag este pusheado a GitHub"

cat <<RUBY
class Certop < Formula
  desc "Visualizar estado de certificados TLS en una flota de servidores"
  homepage "https://github.com/carlosm3011/certop"
  url "${URL}"
  sha256 "${SHA}"
  license "BSD-2-Clause"
  head "https://github.com/carlosm3011/certop.git", branch: "main"

  depends_on "go" => :build

  def install
    # std_go_args ya pone -trimpath y -s -w por su cuenta: aca va solo la
    # version. Sin git no lleva el sufijo +sha que agrega el build local.
    system "go", "build", *std_go_args(ldflags: "-X main.version=#{version}"), "./cmd/certop"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/certop --version")

    # Sin inventario tiene que fallar limpio, no romperse.
    output = shell_output("#{bin}/certop --file no-existe.toml 2>&1", 1)
    assert_match "no-existe.toml", output
  end
end
RUBY
