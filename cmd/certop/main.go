// certop muestra el estado de los certificados TLS de una flota de servidores,
// en una pasada unica o en una pantalla que se refresca estilo top/mtr.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/lacniclabs/certop/internal/inventory"
	"github.com/lacniclabs/certop/internal/probe"
	"github.com/lacniclabs/certop/internal/report"
	"github.com/lacniclabs/certop/internal/ui"
)

// version la sobreescribe el Makefile con -ldflags -X, agregandole la revision
// de git; este valor es el que queda al compilar con go build a secas.
var version = "0.9.1"

type options struct {
	once        bool
	refresh     int
	file        string
	format      string
	warnDays    int
	probeAlways bool
	workers     int
	timeout     time.Duration
	showVersion bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	var opt options
	fs := flag.NewFlagSet("certop", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr, fs) }

	fs.BoolVar(&opt.once, "once", false, "corre una sola vez y termina")
	fs.BoolVar(&opt.once, "1", false, "abreviatura de --once")
	fs.IntVar(&opt.refresh, "refresh", 0, "refresca cada N segundos, estilo top/mtr")
	fs.IntVar(&opt.refresh, "r", 0, "abreviatura de --refresh")
	fs.StringVar(&opt.file, "file", "hosts.toml", "archivo TOML de inventario")
	fs.StringVar(&opt.file, "f", "hosts.toml", "abreviatura de --file")
	fs.StringVar(&opt.format, "format", report.FormatCSV, "formato de salida de --once: csv, table o json")
	fs.IntVar(&opt.warnDays, "warn-days", -1, "exit code 2 si algun destino falla o expira en menos de N dias")
	fs.BoolVar(&opt.probeAlways, "probe-always", false, "resondea las versiones TLS en cada refresco")
	fs.IntVar(&opt.workers, "workers", 32, "cantidad maxima de chequeos concurrentes")
	fs.DurationVar(&opt.timeout, "timeout", 5*time.Second, "timeout por destino")
	fs.BoolVar(&opt.showVersion, "version", false, "muestra la version y termina")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitUsage
	}

	if opt.showVersion {
		fmt.Fprintf(stdout, "certop %s\n", version)
		return report.ExitOK
	}
	if err := validate(&opt, fs); err != nil {
		fmt.Fprintf(stderr, "certop: %v\n", err)
		return report.ExitUsage
	}

	targets, err := inventory.Load(opt.file)
	if err != nil {
		fmt.Fprintf(stderr, "certop: %v\n", err)
		return report.ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	checker := probe.New(opt.timeout, opt.workers, opt.probeAlways)

	if opt.refresh > 0 {
		interval := time.Duration(opt.refresh) * time.Second
		if err := ui.Run(ctx, checker, targets, interval); err != nil {
			fmt.Fprintf(stderr, "certop: %v\n", err)
			return report.ExitUsage
		}
		return report.ExitOK
	}

	results := checker.Run(ctx, targets, nil)
	if err := report.Write(stdout, results, opt.format); err != nil {
		fmt.Fprintf(stderr, "certop: %v\n", err)
		return report.ExitUsage
	}
	return report.ExitCode(results, opt.warnDays)
}

func validate(opt *options, fs *flag.FlagSet) error {
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	onceSet := set["once"] || set["1"]
	refreshSet := set["refresh"] || set["r"]
	if onceSet && refreshSet {
		return errors.New("--once y --refresh son mutuamente excluyentes")
	}
	if refreshSet && opt.refresh < 1 {
		return fmt.Errorf("--refresh necesita un intervalo positivo, se recibio %d", opt.refresh)
	}
	if !slices.Contains(report.Formats, opt.format) {
		return fmt.Errorf("formato %q invalido (validos: %v)", opt.format, report.Formats)
	}
	if opt.workers < 1 {
		return fmt.Errorf("--workers necesita al menos 1, se recibio %d", opt.workers)
	}
	if opt.timeout <= 0 {
		return fmt.Errorf("--timeout debe ser positivo, se recibio %s", opt.timeout)
	}
	// Sin modo explicito se corre una vez.
	return nil
}

func usage(out *os.File, fs *flag.FlagSet) {
	fmt.Fprint(out, `certop - estado de certificados TLS en una flota de servidores

Uso:
  certop [--once|-1] [--refresh|-r N] [--file|-f RUTA] [--format csv|table|json]
         [--warn-days N] [--probe-always] [--workers N] [--timeout D] [--help]

Sin --refresh corre una sola vez y escribe el reporte en stdout.

Exit codes:
  0  todo bien
  1  error de uso, de inventario o de escritura
  2  con --warn-days: algun destino inalcanzable o por vencer

Opciones:
`)
	fs.PrintDefaults()
	fmt.Fprint(out, `
Ejemplos:
  certop -f hosts.toml                        reporte CSV
  certop --once --format table                tabla legible
  certop --once --warn-days 30 >/dev/null     chequeo para cron
  certop --refresh 5                          pantalla estilo top
`)
}
