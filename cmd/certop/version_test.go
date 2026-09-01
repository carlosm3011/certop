package main

import "testing"

// El caso que motiva resolveVersion es `go install`: ahi los -ldflags del
// Makefile no se aplican y la version tiene que salir del build info. Antes
// salia de un literal, y el binario reportaba una version que no era la suya.
func TestResolveVersion(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	t.Run("usa la version que inyecta el Makefile", func(t *testing.T) {
		version = "1.3.1+abc1234"
		if got := resolveVersion(); got != "1.3.1+abc1234" {
			t.Fatalf("resolveVersion() = %q, se esperaba la inyectada", got)
		}
	})

	t.Run("sin inyectar no inventa un numero", func(t *testing.T) {
		version = ""
		got := resolveVersion()
		// El binario de test se compila desde el arbol de trabajo, asi que el
		// build info trae "(devel)" y no hay version real que reportar. Lo que
		// importa es que no aparezca un numero inventado.
		if got != "desconocida" {
			t.Fatalf("resolveVersion() = %q, se esperaba \"desconocida\"", got)
		}
	})
}
