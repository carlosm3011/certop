#!/usr/bin/env bash
#
# Publica una release de certop.
#
# No hay runner con Go, asi que los binarios se compilan aca y se commitean en
# release/. El pipeline de GitLab solo crea el objeto Release apuntando a los
# archivos del repo, y no hace falta ningun token: todo viaja por ssh con la
# llave que ya usas para pushear.
#
#   VERSION=v1.1 make release
#   VERSION=v1.1 make release-dry   # muestra que haria, sin tocar nada
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
RELEASEDIR="${RELEASEDIR:-release}"

# "1.1" y "v1.1" son lo mismo; el tag siempre lleva la v.
RELVERSION="${VERSION#v}"
TAG="v${RELVERSION}"

say "certop ${RELVERSION}  ->  tag ${TAG}, binarios en ${RELEASEDIR}/"

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

say "sincronizando con el remoto"
git fetch -q origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] ||
	die "HEAD no coincide con origin/main; pushea o traete los cambios primero"

if git ls-remote --tags --exit-code origin "refs/tags/${TAG}" >/dev/null 2>&1; then
	die "el tag ${TAG} ya existe en el remoto"
fi

# ---- compilar y firmar -------------------------------------------------------

say "compilando"
make dist VERSION="$RELVERSION"

say "generando SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
	sum() { sha256sum "$@"; }
else
	sum() { shasum -a 256 "$@"; }
fi
(cd "$DISTDIR" && sum certop-* >SHA256SUMS)
sed 's/^/    /' "${DISTDIR}/SHA256SUMS"

# ---- publicar en el repo -----------------------------------------------------
# Los binarios versionados van en release/; dist/ sigue ignorado, para que
# compilar durante el desarrollo no ensucie el arbol.

say "copiando a ${RELEASEDIR}/"
run mkdir -p "$RELEASEDIR"
for file in $(cd "$DISTDIR" && ls certop-* SHA256SUMS); do
	run cp "${DISTDIR}/${file}" "${RELEASEDIR}/${file}"
done

# Que el default del Makefile siga a la ultima release, para que un `make build`
# posterior no vuelva a decir la version vieja.
say "fijando VERSION=${RELVERSION} en el Makefile"
if [ "$DRY_RUN" = 1 ]; then
	printf '   [dry-run] sed VERSION ?= %s\n' "$RELVERSION"
else
	tmp=$(mktemp)
	sed "s/^VERSION ?= .*/VERSION ?= ${RELVERSION}/" Makefile >"$tmp"
	grep -q "^VERSION ?= ${RELVERSION}\$" "$tmp" ||
		die "no pude fijar VERSION en el Makefile"
	mv "$tmp" Makefile
fi

notes="${NOTES:-certop ${RELVERSION}}"

say "commiteando"
run git add "$RELEASEDIR" Makefile
if [ "$DRY_RUN" != 1 ] && git diff --cached --quiet; then
	die "no hay nada que commitear: ¿ya estaba liberada esta version?"
fi
run git commit -m "certop ${RELVERSION}: binarios de la release"

# El commit tiene que estar en el remoto antes que el tag: la release enlaza a
# los archivos del repo en ese tag.
say "pusheando main"
run git push origin main

say "creando y pusheando ${TAG} (dispara el pipeline de release)"
run git tag -a "$TAG" -m "$notes"
run git push origin "$TAG"

say "listo"
if [ "$DRY_RUN" = 1 ]; then
	printf '    (dry-run: no se modifico, commiteo ni pusheo nada)\n'
else
	remote=$(git remote get-url origin)
	web=$(printf '%s' "$remote" | sed -E 's#^git@([^:]+):#https://\1/#; s#\.git$##')
	printf '    pipeline: %s/-/pipelines\n' "$web"
	printf '    release:  %s/-/releases/%s\n' "$web" "$TAG"
fi
