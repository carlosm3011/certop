#!/usr/bin/env bash
#
# Publica una release de certop.
#
# No hay runner con Go, asi que los binarios se compilan y se suben desde aca;
# el pipeline de GitLab solo crea el objeto Release apuntando a lo ya subido.
# Por eso el orden importa: primero se sube, despues se pushea el tag.
#
#   VERSION=v1.1 make release
#   DRY_RUN=1 VERSION=v1.1 make release   # muestra que haria, sin tocar nada
#
set -euo pipefail

die() { printf 'release: %s\n' "$*" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
run() {
	if [ "$DRY_RUN" = 1 ]; then
		printf '   [dry-run] %s\n' "$*"
	else
		"$@"
	fi
}

VERSION="${VERSION:?falta VERSION}"
DRY_RUN="${DRY_RUN:-0}"
DISTDIR="${DISTDIR:-dist}"
PACKAGE="${PACKAGE:-certop}"

# "1.1" y "v1.1" son lo mismo; el tag siempre lleva la v.
RELVERSION="${VERSION#v}"
TAG="v${RELVERSION}"

# El registry de paquetes generico exige una version de tres componentes, asi
# que 1.1 se sube como 1.1.0. El tag y el binario siguen diciendo 1.1.
pkgversion() {
	local v="$1" dots
	dots=$(printf '%s' "$v" | tr -cd '.' | wc -c | tr -d ' ')
	case "$dots" in
	0) printf '%s.0.0' "$v" ;;
	1) printf '%s.0' "$v" ;;
	*) printf '%s' "$v" ;;
	esac
}
PKGVERSION=$(pkgversion "$RELVERSION")

# Host y proyecto salen del remoto, para no hardcodear la instancia; se pueden
# fijar a mano si el remoto no tiene la forma esperada.
remote=$(git remote get-url origin)
host="${GITLAB_HOST:-$(printf '%s' "$remote" | sed -E 's#^git@([^:]+):.*#\1#; s#^https?://([^/]+)/.*#\1#')}"
path="${GITLAB_PROJECT:-$(printf '%s' "$remote" | sed -E 's#^git@[^:]+:##; s#^https?://[^/]+/##; s#\.git$##')}"

# Si el remoto no es una URL de GitLab, mejor frenar que armar una URL absurda.
case "$host" in
"" | */* | *\ *)
	die "no pude deducir el host de GitLab de '${remote}'; fija GITLAB_HOST y GITLAB_PROJECT"
	;;
esac
case "$path" in
*/*) ;;
*) die "no pude deducir el proyecto de '${remote}'; fija GITLAB_PROJECT (grupo/proyecto)" ;;
esac

api="https://${host}/api/v4"
project=$(printf '%s' "$path" | sed 's#/#%2F#g')

say "certop ${RELVERSION}  ->  tag ${TAG}, paquete ${PACKAGE}/${PKGVERSION}"
printf '    proyecto: %s en %s\n' "$path" "$host"

# ---- controles previos -------------------------------------------------------
# Todos antes de tocar nada: una release a medias es peor que una que no salio.

[ -z "$(git status --porcelain)" ] ||
	die "el arbol de trabajo tiene cambios sin commitear"

branch=$(git branch --show-current)
[ "$branch" = "main" ] ||
	die "estas en '$branch'; las releases salen de main"

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
	die "el tag ${TAG} ya existe localmente"
fi

say "verificando que el commit este en el remoto"
git fetch -q origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] ||
	die "HEAD no coincide con origin/main; pushea el commit antes de liberarlo"

if git ls-remote --tags --exit-code origin "refs/tags/${TAG}" >/dev/null 2>&1; then
	die "el tag ${TAG} ya existe en el remoto"
fi

if [ "$DRY_RUN" != 1 ]; then
	[ -n "${GITLAB_TOKEN:-}" ] ||
		die "falta GITLAB_TOKEN (token con scope api) para subir los binarios"
fi

# ---- compilar y firmar -------------------------------------------------------

say "compilando ${DISTDIR}/"
make dist VERSION="$RELVERSION"

say "generando SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
	sum() { sha256sum "$@"; }
else
	sum() { shasum -a 256 "$@"; }
fi
(cd "$DISTDIR" && sum certop-* >SHA256SUMS)
sed 's/^/    /' "${DISTDIR}/SHA256SUMS"

# ---- subir al package registry ----------------------------------------------

assets=$(cd "$DISTDIR" && ls certop-* SHA256SUMS)
for file in $assets; do
	url="${api}/projects/${project}/packages/generic/${PACKAGE}/${PKGVERSION}/${file}"
	say "subiendo ${file}"
	if [ "$DRY_RUN" = 1 ]; then
		printf '   [dry-run] PUT %s\n' "$url"
	else
		curl --fail-with-body --silent --show-error \
			--header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
			--upload-file "${DISTDIR}/${file}" "$url" >/dev/null
	fi
done

# ---- taggear y pushear -------------------------------------------------------
# El push del tag dispara el pipeline que crea la Release. Va ultimo, con los
# binarios ya arriba.

notes="${NOTES:-certop ${RELVERSION}}"
say "creando tag ${TAG}"
run git tag -a "$TAG" -m "$notes"

say "pusheando ${TAG} (dispara el pipeline de release)"
run git push origin "$TAG"

say "listo"
if [ "$DRY_RUN" = 1 ]; then
	printf '    (dry-run: no se subio ni se pusheo nada)\n'
else
	printf '    seguimiento: https://%s/%s/-/pipelines\n' "$host" "$path"
	printf '    release:     https://%s/%s/-/releases/%s\n' "$host" "$path" "$TAG"
fi
