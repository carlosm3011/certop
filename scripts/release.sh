#!/usr/bin/env bash
#
# Publica una release de certop en los dos remotos: el GitLab interno y el
# GitHub publico.
#
# El GitLab interno no tiene runner con Go, asi que los binarios se compilan
# aca y se commitean en release/. Los dos pipelines solo crean el objeto Release
# apuntando a esos archivos, de modo que los assets de los dos lados son byte a
# byte los mismos. No hace falta ningun token: git viaja por ssh con la llave
# que ya usas, y cada CI usa el token que se inyecta solo.
#
#   VERSION=v1.3.0 make release
#   VERSION=v1.3.0 make release-dry   # muestra que haria, sin tocar nada
#
# REMOTES pisa la lista de remotos (default: "origin github"); los que no estan
# configurados se saltean con un aviso.
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

# "1.3.0" y "v1.3.0" son lo mismo; el tag siempre lleva la v.
RELVERSION="${VERSION#v}"
TAG="v${RELVERSION}"

# Tres numeros, no dos. El proxy de modulos de Go solo reconoce semver canonico:
# un tag "v1.3" existe en el repo pero queda invisible para `go install`, que es
# justamente como quedo v1.1. Mejor rechazarlo antes de compilar nada.
printf '%s' "$RELVERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$' ||
	die "VERSION='${VERSION}' no es semver de tres numeros (ej. 1.3.0): go install no veria ese tag"

say "certop ${RELVERSION}  ->  tag ${TAG}, binarios en ${RELEASEDIR}/"

# ---- remotos -----------------------------------------------------------------
# La release sale hacia los dos lados. Un clon que solo tenga uno igual puede
# liberar, para no obligar a configurar el otro.

REMOTES="${REMOTES:-origin github}"
remotes=""
for remote in $REMOTES; do
	if git remote get-url "$remote" >/dev/null 2>&1; then
		remotes="${remotes}${remotes:+ }${remote}"
	else
		say "aviso: el remoto '${remote}' no esta configurado, se saltea"
	fi
done
[ -n "$remotes" ] || die "no hay ninguno de estos remotos: ${REMOTES}"
say "remotos: ${remotes}"

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

say "sincronizando con los remotos"
for remote in $remotes; do
	git fetch -q "$remote" main
	[ "$(git rev-parse HEAD)" = "$(git rev-parse "${remote}/main")" ] ||
		die "HEAD no coincide con ${remote}/main; pushea o traete los cambios primero"

	if git ls-remote --tags --exit-code "$remote" "refs/tags/${TAG}" >/dev/null 2>&1; then
		die "el tag ${TAG} ya existe en ${remote}"
	fi
done

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

# El commit tiene que estar en los remotos antes que el tag: la release de
# GitLab enlaza a los archivos del repo en ese tag.
say "pusheando main"
for remote in $remotes; do
	run git push "$remote" main
done

say "creando ${TAG}"
run git tag -a "$TAG" -m "$notes"
for remote in $remotes; do
	say "pusheando ${TAG} a ${remote} (dispara el pipeline de release)"
	run git push "$remote" "$TAG"
done

say "listo"
if [ "$DRY_RUN" = 1 ]; then
	printf '    (dry-run: no se modifico, commiteo ni pusheo nada)\n'
else
	for remote in $remotes; do
		url=$(git remote get-url "$remote")
		web=$(printf '%s' "$url" |
			sed -E 's#^git@([^:]+):#https://\1/#; s#^ssh://git@([^/]+)/#https://\1/#; s#\.git$##')
		case "$web" in
		https://github.com/*)
			printf '    %-8s %s/actions\n' "$remote" "$web"
			printf '    %-8s %s/releases/tag/%s\n' "$remote" "$web" "$TAG"
			;;
		https://*)
			printf '    %-8s %s/-/pipelines\n' "$remote" "$web"
			printf '    %-8s %s/-/releases/%s\n' "$remote" "$web" "$TAG"
			;;
		*)
			printf '    %-8s %s (no parece una URL web)\n' "$remote" "$url"
			;;
		esac
	done
fi
