#!/usr/bin/env bash
#
# Crea el objeto Release en GitLab. Corre en el pipeline, disparado por el push
# de un tag hecho con `make release`.
#
# Los binarios estan commiteados en release/, asi que la release enlaza a los
# archivos crudos del repo en ese tag. No hace falta ningun token: alcanza con
# el CI_JOB_TOKEN que GitLab inyecta solo.
#
# Pensado para un shell runner: solo necesita git y curl. Si hay jq disponible
# se usa para armar el JSON y aprovechar el mensaje del tag como descripcion.
#
set -euo pipefail

die() { printf 'gitlab-release: %s\n' "$*" >&2; exit 1; }

: "${CI_COMMIT_TAG:?este job solo corre sobre un tag}"
: "${CI_API_V4_URL:?}"
: "${CI_PROJECT_ID:?}"
: "${CI_PROJECT_URL:?}"
: "${CI_JOB_TOKEN:?}"

RELEASEDIR="${RELEASEDIR:-release}"
RELVERSION="${CI_COMMIT_TAG#v}"
assets="certop-linux-amd64 certop-darwin-arm64 SHA256SUMS"

# Un tag pusheado a mano no trae los binarios: mejor fallar aca que crear una
# release con links rotos. Como estan en el repo, alcanza con mirar el checkout.
for file in $assets; do
	[ -f "${RELEASEDIR}/${file}" ] ||
		die "falta ${RELEASEDIR}/${file} en el tag ${CI_COMMIT_TAG}. ¿Se libero con 'make release'?"
done

# Los binarios se sirven crudos desde el repo, fijados al tag.
base="${CI_PROJECT_URL}/-/raw/${CI_COMMIT_TAG}/${RELEASEDIR}"

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
	# Sin jq se usa una descripcion controlada: escapar el mensaje del tag a
	# mano en JSON es pedir problemas.
	desc="certop ${RELVERSION}. Binarios commiteados en ${RELEASEDIR}/."
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
