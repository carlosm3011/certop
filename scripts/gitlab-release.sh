#!/usr/bin/env bash
#
# Crea el objeto Release en GitLab. Corre en el pipeline, disparado por el push
# de un tag; los binarios ya fueron subidos al package registry por
# `make release` desde la maquina del operador, porque no hay runner con Go.
#
# Pensado para un shell runner: solo necesita git y curl. Si hay jq disponible
# se usa para armar el JSON y aprovechar el mensaje del tag como descripcion.
#
set -euo pipefail

die() { printf 'gitlab-release: %s\n' "$*" >&2; exit 1; }

: "${CI_COMMIT_TAG:?este job solo corre sobre un tag}"
: "${CI_API_V4_URL:?}"
: "${CI_PROJECT_ID:?}"
: "${CI_JOB_TOKEN:?}"

PACKAGE="${PACKAGE:-certop}"
RELVERSION="${CI_COMMIT_TAG#v}"

# Mismo criterio que scripts/release.sh: el paquete usa tres componentes.
dots=$(printf '%s' "$RELVERSION" | tr -cd '.' | wc -c | tr -d ' ')
case "$dots" in
0) PKGVERSION="${RELVERSION}.0.0" ;;
1) PKGVERSION="${RELVERSION}.0" ;;
*) PKGVERSION="$RELVERSION" ;;
esac

base="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/${PACKAGE}/${PKGVERSION}"
assets="certop-linux-amd64 certop-darwin-arm64 SHA256SUMS"

# Un tag pusheado a mano no tiene binarios arriba: mejor fallar aca que crear
# una release con links rotos.
for file in $([ "${DRY_RUN:-0}" = 1 ] || echo $assets); do
	code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
		--header "JOB-TOKEN: ${CI_JOB_TOKEN}" "${base}/${file}")
	case "$code" in
	200 | 302) ;;
	*) die "falta ${file} en el package registry (HTTP ${code}). ¿Se libero con 'make release'?" ;;
	esac
done

# Descripcion: el mensaje del tag si se puede, y si no una generada.
message="${CI_COMMIT_TAG_MESSAGE:-}"
if [ -z "$message" ]; then
	message=$(git tag -l --format='%(contents)' "$CI_COMMIT_TAG" 2>/dev/null || true)
fi
[ -n "$message" ] || message="certop ${RELVERSION}"

payload=$(mktemp)
trap 'rm -f "$payload"' EXIT

if command -v jq >/dev/null 2>&1; then
	jq -n \
		--arg name "certop ${RELVERSION}" \
		--arg tag "$CI_COMMIT_TAG" \
		--arg desc "$message" \
		--arg base "$base" \
		'{
			name: $name,
			tag_name: $tag,
			description: $desc,
			assets: {
				links: [
					{name: "certop-linux-amd64",  url: ($base + "/certop-linux-amd64"),  link_type: "package"},
					{name: "certop-darwin-arm64", url: ($base + "/certop-darwin-arm64"), link_type: "package"},
					{name: "SHA256SUMS",          url: ($base + "/SHA256SUMS"),          link_type: "other"}
				]
			}
		}' >"$payload"
else
	# Sin jq: se escapa a mano y se usa una descripcion controlada, para no
	# meter el mensaje del tag sin poder escaparlo bien.
	desc="certop ${RELVERSION}. Binarios en el package registry del proyecto."
	cat >"$payload" <<JSON
{
  "name": "certop ${RELVERSION}",
  "tag_name": "${CI_COMMIT_TAG}",
  "description": "${desc}",
  "assets": {
    "links": [
      {"name": "certop-linux-amd64",  "url": "${base}/certop-linux-amd64",  "link_type": "package"},
      {"name": "certop-darwin-arm64", "url": "${base}/certop-darwin-arm64", "link_type": "package"},
      {"name": "SHA256SUMS",          "url": "${base}/SHA256SUMS",          "link_type": "other"}
    ]
  }
}
JSON
fi

if [ "${DRY_RUN:-0}" = 1 ]; then
	printf 'POST %s/projects/%s/releases\n' "$CI_API_V4_URL" "$CI_PROJECT_ID"
	cat "$payload"
	exit 0
fi

curl --fail-with-body --silent --show-error \
	--request POST \
	--header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
	--header "Content-Type: application/json" \
	--data @"$payload" \
	"${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/releases" >/dev/null

printf 'release %s creada\n' "$CI_COMMIT_TAG"
