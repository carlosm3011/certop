// Package ui dibuja la pantalla de refresco estilo top/mtr sobre tcell.
package ui

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/lacniclabs/certop/internal/inventory"
	"github.com/lacniclabs/certop/internal/probe"
)

// Modos de ordenamiento, ciclados con la tecla 's'.
const (
	sortByGroup = iota
	sortByHost
	sortByExpiry
	sortModes
)

var sortNames = [sortModes]string{"grupo", "host", "expira"}

// App mantiene el estado de la pantalla.
type App struct {
	screen   tcell.Screen
	checker  *probe.Checker
	targets  []inventory.Target
	interval time.Duration

	mu        sync.Mutex
	results   []probe.Result
	filled    []bool
	running   bool
	paused    bool
	sortMode  int
	lastCycle time.Time
	lastDur   time.Duration

	redraw chan struct{}
}

// Run toma la terminal y refresca hasta que el usuario salga o se cancele ctx.
func Run(ctx context.Context, checker *probe.Checker, targets []inventory.Target, interval time.Duration) error {
	screen, err := tcell.NewScreen()
	if err != nil {
		return fmt.Errorf("no se pudo abrir la terminal: %w", err)
	}
	if err := screen.Init(); err != nil {
		return fmt.Errorf("no se pudo inicializar la terminal: %w", err)
	}
	defer screen.Fini()

	return newApp(screen, checker, targets, interval).loop(ctx)
}

func newApp(screen tcell.Screen, checker *probe.Checker, targets []inventory.Target, interval time.Duration) *App {
	a := &App{
		screen:   screen,
		checker:  checker,
		targets:  targets,
		interval: interval,
		results:  make([]probe.Result, len(targets)),
		filled:   make([]bool, len(targets)),
		redraw:   make(chan struct{}, 1),
	}
	for i, t := range targets {
		a.results[i] = probe.Result{Target: t}
	}
	return a
}

func (a *App) loop(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	events := make(chan tcell.Event, 16)
	go func() {
		defer close(events)
		for {
			ev := a.screen.PollEvent()
			if ev == nil { // la pantalla se cerro
				return
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	cycle := time.NewTicker(a.interval)
	defer cycle.Stop()
	clock := time.NewTicker(time.Second)
	defer clock.Stop()

	a.startCycle(ctx)
	a.draw()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-cycle.C:
			if !a.isPaused() {
				a.startCycle(ctx)
			}
		case <-clock.C:
			a.draw()
		case <-a.redraw:
			a.draw()
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if quit := a.handle(ctx, ev); quit {
				return nil
			}
		}
	}
}

// handle procesa un evento de terminal y devuelve true si hay que salir.
func (a *App) handle(ctx context.Context, ev tcell.Event) bool {
	switch ev := ev.(type) {
	case *tcell.EventResize:
		a.screen.Sync()
		a.draw()
	case *tcell.EventKey:
		switch ev.Key() {
		case tcell.KeyEscape, tcell.KeyCtrlC:
			return true
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'q', 'Q':
				return true
			case 'r', 'R':
				a.startCycle(ctx)
			case 'p', 'P':
				a.checker.InvalidateVersions()
				a.startCycle(ctx)
			case 's', 'S':
				a.mu.Lock()
				a.sortMode = (a.sortMode + 1) % sortModes
				a.mu.Unlock()
				a.draw()
			case ' ':
				a.mu.Lock()
				a.paused = !a.paused
				a.mu.Unlock()
				a.draw()
			}
		}
	}
	return false
}

func (a *App) isPaused() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.paused
}

// startCycle lanza una pasada completa si no hay otra en curso. Si la anterior
// todavia corre se saltea, para que un destino lento no encime los ciclos.
func (a *App) startCycle(ctx context.Context) {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return
	}
	a.running = true
	a.mu.Unlock()

	go func() {
		started := time.Now()
		a.checker.Run(ctx, a.targets, func(i int, r probe.Result) {
			a.mu.Lock()
			a.results[i] = r
			a.filled[i] = true
			a.mu.Unlock()
			a.requestDraw()
		})
		a.mu.Lock()
		a.running = false
		a.lastCycle = time.Now()
		a.lastDur = time.Since(started)
		a.mu.Unlock()
		a.requestDraw()
	}()
}

// requestDraw pide un redibujado sin bloquear; los pedidos se coalescen.
func (a *App) requestDraw() {
	select {
	case a.redraw <- struct{}{}:
	default:
	}
}

type columns struct {
	group, host, port, tcp, expiry, tlsCol, status, issuer int
}

func (a *App) layout(width int, results []probe.Result) columns {
	c := columns{port: 6, tcp: 9, expiry: 7, tlsCol: 4, status: 18}
	c.group, c.host = 5, 10
	for _, r := range results {
		c.group = max(c.group, len(r.Group))
		c.host = max(c.host, len(r.Host))
	}
	c.group = min(c.group, 20)
	c.host = min(c.host, 40)

	used := c.group + c.host + c.port + c.tcp + c.expiry + c.tlsCol + c.status + 7
	c.issuer = max(width-used, 0)
	return c
}

func (a *App) draw() {
	a.mu.Lock()
	results := make([]probe.Result, len(a.results))
	copy(results, a.results)
	filled := make([]bool, len(a.filled))
	copy(filled, a.filled)
	running, paused, sortMode := a.running, a.paused, a.sortMode
	lastCycle, lastDur := a.lastCycle, a.lastDur
	a.mu.Unlock()

	a.screen.Clear()
	width, height := a.screen.Size()
	if width < 20 || height < 4 {
		a.screen.Show()
		return
	}
	cols := a.layout(width, results)
	order := sortOrder(results, sortMode)

	// Encabezado.
	head := fmt.Sprintf("certop  %d destinos  refresco %s  orden %s",
		len(results), a.interval, sortNames[sortMode])
	switch {
	case running:
		head += "  [chequeando]"
	case !lastCycle.IsZero():
		head += fmt.Sprintf("  ultima %s (%s)", lastCycle.Format("15:04:05"), lastDur.Round(time.Millisecond))
	}
	if paused {
		head += "  [PAUSA]"
	}
	if n := countWarn(results, filled); n > 0 {
		head += fmt.Sprintf("  %d con problemas", n)
	}
	a.text(0, 0, width, tcell.StyleDefault.Bold(true), head)

	// Cabecera de columnas.
	headerStyle := tcell.StyleDefault.Reverse(true)
	for x := 0; x < width; x++ {
		a.screen.SetContent(x, 1, ' ', nil, headerStyle)
	}
	a.row(1, cols, headerStyle, headerStyle,
		"GRUPO", "HOST", "PUERTO", "TCP", "EXPIRA", "TLS", "ESTADO", "EMISOR")

	// Filas.
	visible := height - 3
	for i, idx := range order {
		if i >= visible {
			break
		}
		r := results[idx]
		base := tcell.StyleDefault
		if !filled[idx] {
			base = base.Dim(true)
		}
		a.row(i+2, cols, base, rowStyle(r, filled[idx]),
			r.Group, r.Host, r.Port, r.TCP.String(), r.ExpiryText(),
			r.TLSDigits(), r.CertStatus.String(), issuerText(r, filled[idx]))
	}
	if len(order) > visible {
		a.text(0, height-2, width, tcell.StyleDefault.Dim(true),
			fmt.Sprintf("... %d destinos mas (agrandar la terminal)", len(order)-visible))
	}

	// Pie.
	foot := "q salir  r refrescar  p resondear TLS  s ordenar  espacio pausa   " +
		"tls: 1.0/1.1/1.2/1.3, digito=acepta, -=rechaza, ?=sin dato"
	a.text(0, height-1, width, tcell.StyleDefault.Dim(true), foot)

	a.screen.Show()
}

// row dibuja una fila completa. base pinta las columnas neutras y accent las
// que reflejan el estado del destino.
func (a *App) row(y int, c columns, base, accent tcell.Style, group, host, port, tcp, expiry, tlsCol, status, issuer string) {
	x := 0
	x += a.text(x, y, c.group, base, group) + 1
	x += a.text(x, y, c.host, base, host) + 1
	x += a.text(x, y, c.port, base, port) + 1
	x += a.text(x, y, c.tcp, accent, tcp) + 1
	x += a.text(x, y, c.expiry, accent, expiry) + 1
	x += a.text(x, y, c.tlsCol, base, tlsCol) + 1
	x += a.text(x, y, c.status, accent, status) + 1
	a.text(x, y, c.issuer, base, issuer)
}

// text escribe s recortado a maxw celdas y devuelve maxw.
func (a *App) text(x, y, maxw int, style tcell.Style, s string) int {
	if maxw <= 0 {
		return 0
	}
	i := 0
	for _, r := range s {
		if i >= maxw {
			break
		}
		a.screen.SetContent(x+i, y, r, nil, style)
		i++
	}
	for ; i < maxw; i++ {
		a.screen.SetContent(x+i, y, ' ', nil, style)
	}
	return maxw
}

// rowStyle elige el color segun la urgencia del destino.
func rowStyle(r probe.Result, filled bool) tcell.Style {
	s := tcell.StyleDefault
	if !filled {
		return s.Dim(true)
	}
	switch {
	case !r.TCP.OK(), r.CertStatus == probe.CertExpired:
		return s.Foreground(tcell.ColorRed).Bold(true)
	case !r.HasCert():
		return s.Foreground(tcell.ColorRed)
	case r.DaysLeft < 7:
		return s.Foreground(tcell.ColorRed).Bold(true)
	case r.DaysLeft < 30, !r.CertStatus.OK():
		return s.Foreground(tcell.ColorYellow)
	default:
		return s.Foreground(tcell.ColorGreen)
	}
}

func issuerText(r probe.Result, filled bool) string {
	if !filled {
		return "..."
	}
	if r.Issuer == "" {
		if r.Err != nil {
			return r.Err.Error()
		}
		return "-"
	}
	return r.Issuer
}

func countWarn(results []probe.Result, filled []bool) int {
	n := 0
	for i, r := range results {
		if !filled[i] {
			continue
		}
		if !r.TCP.OK() || !r.HasCert() || !r.CertStatus.OK() || r.DaysLeft < 30 {
			n++
		}
	}
	return n
}

// sortOrder devuelve los indices en el orden de visualizacion pedido.
func sortOrder(results []probe.Result, mode int) []int {
	order := make([]int, len(results))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(x, y int) bool {
		a, b := results[order[x]], results[order[y]]
		switch mode {
		case sortByHost:
			if a.Host != b.Host {
				return a.Host < b.Host
			}
			return a.Port < b.Port
		case sortByExpiry:
			// Lo inalcanzable primero: es lo que hay que mirar ya.
			if a.HasCert() != b.HasCert() {
				return !a.HasCert()
			}
			if a.DaysLeft != b.DaysLeft {
				return a.DaysLeft < b.DaysLeft
			}
			return a.Host < b.Host
		default:
			if a.Group != b.Group {
				return a.Group < b.Group
			}
			if a.Host != b.Host {
				return a.Host < b.Host
			}
			return a.Port < b.Port
		}
	})
	return order
}
