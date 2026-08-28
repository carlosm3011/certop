// Package ui dibuja la pantalla de refresco estilo top/mtr sobre tcell.
package ui

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/carlosm3011/certop/internal/inventory"
	"github.com/carlosm3011/certop/internal/probe"
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
	warnDays int

	mu sync.Mutex
	// rows se indexa por Result.Key(): un nombre se expande en una fila por
	// direccion, y el conjunto puede cambiar entre pasadas si cambia el DNS.
	rows      map[string]row
	cycle     uint64
	running   bool
	paused    bool
	sortMode  int
	lastCycle time.Time
	lastDur   time.Duration

	redraw chan struct{}
}

// row es una fila en pantalla. cycle registra en que pasada se la vio por
// ultima vez, para poder descartar las que el DNS dejo de devolver; fresh
// distingue una fila ya chequeada de un placeholder recien creado.
type row struct {
	result probe.Result
	cycle  uint64
	fresh  bool
}

// Run toma la terminal y refresca hasta que el usuario salga o se cancele ctx.
func Run(ctx context.Context, checker *probe.Checker, targets []inventory.Target, interval time.Duration, warnDays int) error {
	screen, err := tcell.NewScreen()
	if err != nil {
		return fmt.Errorf("no se pudo abrir la terminal: %w", err)
	}
	if err := screen.Init(); err != nil {
		return fmt.Errorf("no se pudo inicializar la terminal: %w", err)
	}
	defer screen.Fini()

	return newApp(screen, checker, targets, interval, warnDays).loop(ctx)
}

func newApp(screen tcell.Screen, checker *probe.Checker, targets []inventory.Target, interval time.Duration, warnDays int) *App {
	a := &App{
		screen:   screen,
		checker:  checker,
		targets:  targets,
		interval: interval,
		warnDays: warnDays,
		rows:     make(map[string]row, len(targets)),
		redraw:   make(chan struct{}, 1),
	}
	// Placeholders para que la pantalla muestre el inventario completo antes
	// de que termine la primera pasada.
	for _, t := range targets {
		r := probe.Result{Target: t}
		a.rows[r.Key()] = row{result: r}
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

		a.mu.Lock()
		a.cycle++
		cycle := a.cycle
		a.mu.Unlock()

		a.checker.Run(ctx, a.targets, func(r probe.Result) {
			key := r.Key()
			a.mu.Lock()
			// El placeholder del destino se retira apenas llega su primera
			// direccion; si no, la lista creceria hasta placeholders+filas
			// antes de podarse al cerrar el ciclo. Cuando la resolucion falla
			// la fila ES la del placeholder, y hay que conservarla.
			if ph := (probe.Result{Target: r.Target}).Key(); ph != key {
				if old, ok := a.rows[ph]; ok && !old.fresh {
					delete(a.rows, ph)
				}
			}
			a.rows[key] = row{result: r, cycle: cycle, fresh: true}
			a.mu.Unlock()
			a.requestDraw()
		})

		a.mu.Lock()
		// Las filas que esta pasada no toco ya no existen (el DNS dejo de
		// devolver esa direccion). Se descartan recien al final del ciclo,
		// para no vaciar la pantalla mientras la pasada corre.
		for key, r := range a.rows {
			if r.cycle != cycle {
				delete(a.rows, key)
			}
		}
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
	group, host, af, ip, port, tcp, expiry, tlsCol, status, issuer int
}

// layout reparte el ancho disponible. Las columnas de ancho fijo se sirven
// primero; el resto se reparte por prioridad entre host, grupo, IP y emisor,
// de modo que la suma nunca exceda el ancho de la terminal. En una pantalla
// angosta cae primero el emisor, despues la IP, y recien ahi se recortan los
// nombres.
func (a *App) layout(width int, results []probe.Result) columns {
	c := columns{af: 2, port: 6, tcp: 9, expiry: 7, tlsCol: 4, status: 18}
	c.group, c.host = 5, 10
	ipWidth := 0
	for _, r := range results {
		c.group = max(c.group, len(r.Group))
		c.host = max(c.host, len(r.Host))
		ipWidth = max(ipWidth, len(r.IPText()))
	}
	c.group = min(c.group, 20)
	c.host = min(c.host, 40)

	const gaps = 9 // un espacio entre columnas
	rigid := c.af + c.port + c.tcp + c.expiry + c.tlsCol + c.status + gaps
	avail := max(width-rigid, 0)

	// El host es la identidad de la fila, asi que se sirve primero.
	c.host = min(c.host, avail)
	avail -= c.host
	c.group = min(c.group, avail)
	avail -= c.group
	c.ip = min(ipWidth, avail)
	avail -= c.ip
	c.issuer = avail
	return c
}

func (a *App) draw() {
	a.mu.Lock()
	rows := make([]row, 0, len(a.rows))
	for _, r := range a.rows {
		rows = append(rows, r)
	}
	running, paused, sortMode := a.running, a.paused, a.sortMode
	lastCycle, lastDur := a.lastCycle, a.lastDur
	a.mu.Unlock()

	// El mapa no tiene orden: siempre se reordena antes de dibujar.
	sortRows(rows, sortMode)

	a.screen.Clear()
	width, height := a.screen.Size()
	if width < 20 || height < 4 {
		a.screen.Show()
		return
	}
	results := make([]probe.Result, len(rows))
	for i, r := range rows {
		results[i] = r.result
	}
	cols := a.layout(width, results)

	// Encabezado.
	head := fmt.Sprintf("certop  %d filas  refresco %s  orden %s",
		len(rows), a.interval, sortNames[sortMode])
	switch {
	case running:
		head += "  [chequeando]"
	case !lastCycle.IsZero():
		head += fmt.Sprintf("  ultima %s (%s)", lastCycle.Format("15:04:05"), lastDur.Round(time.Millisecond))
	}
	if paused {
		head += "  [PAUSA]"
	}
	problems, warnings := counts(rows, a.warnDays)
	if problems > 0 {
		head += fmt.Sprintf("  %d con problemas", problems)
	}
	if warnings > 0 {
		head += fmt.Sprintf("  %d por vencer (<%dd)", warnings, a.warnDays)
	}
	a.text(0, 0, width, tcell.StyleDefault.Bold(true), head)

	// Cabecera de columnas.
	headerStyle := tcell.StyleDefault.Reverse(true)
	for x := 0; x < width; x++ {
		a.screen.SetContent(x, 1, ' ', nil, headerStyle)
	}
	a.row(1, cols, headerStyle, headerStyle,
		"GRUPO", "HOST", "AF", "IP", "PUERTO", "TCP", "EXPIRA", "TLS", "ESTADO", "EMISOR")

	// Filas.
	visible := height - 3
	for i, r := range rows {
		if i >= visible {
			break
		}
		base := tcell.StyleDefault
		if !r.fresh {
			base = base.Dim(true)
		}
		a.row(i+2, cols, base, rowStyle(r.result, r.fresh, a.warnDays),
			r.result.Group, r.result.Host, r.result.AFText(), r.result.IPText(),
			r.result.Port, r.result.TCP.String(), r.result.ExpiryText(),
			r.result.TLSDigits(), r.result.CertStatus.String(),
			issuerText(r.result, r.fresh))
	}
	if len(rows) > visible {
		a.text(0, height-2, width, tcell.StyleDefault.Dim(true),
			fmt.Sprintf("... %d filas mas (agrandar la terminal)", len(rows)-visible))
	}

	// Pie.
	foot := "q salir  r refrescar  p resondear TLS  s ordenar  espacio pausa   " +
		"tls: 1.0/1.1/1.2/1.3, digito=acepta, -=rechaza, ?=sin dato"
	a.text(0, height-1, width, tcell.StyleDefault.Dim(true), foot)

	a.screen.Show()
}

// row dibuja una fila completa. base pinta las columnas neutras y accent las
// que reflejan el estado del destino.
func (a *App) row(y int, c columns, base, accent tcell.Style, group, host, af, ip, port, tcp, expiry, tlsCol, status, issuer string) {
	x := 0
	x += a.text(x, y, c.group, base, group) + 1
	x += a.text(x, y, c.host, base, host) + 1
	x += a.text(x, y, c.af, base, af) + 1
	if c.ip > 0 {
		x += a.text(x, y, c.ip, base, ip) + 1
	}
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

// rowStyle colorea la fila segun su severidad: rojo para los problemas,
// amarillo para lo que esta por vencer, verde para el resto.
func rowStyle(r probe.Result, fresh bool, warnDays int) tcell.Style {
	s := tcell.StyleDefault
	if !fresh {
		return s.Dim(true)
	}
	switch r.Severity(warnDays) {
	case probe.SevProblem:
		return s.Foreground(tcell.ColorRed).Bold(true)
	case probe.SevWarning:
		// Menos de una semana ya es casi un problema.
		if r.DaysLeft < 7 {
			return s.Foreground(tcell.ColorYellow).Bold(true)
		}
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

// counts separa las filas ya chequeadas en problemas y avisos por vencimiento.
func counts(rows []row, warnDays int) (problems, warnings int) {
	for _, r := range rows {
		if !r.fresh {
			continue
		}
		switch r.result.Severity(warnDays) {
		case probe.SevProblem:
			problems++
		case probe.SevWarning:
			warnings++
		}
	}
	return problems, warnings
}

// sortRows ordena las filas en el lugar. AF e IP entran como desempate en los
// tres modos para que las filas de un mismo host queden juntas y en el mismo
// orden entre pasadas.
func sortRows(rows []row, mode int) {
	sort.SliceStable(rows, func(x, y int) bool {
		a, b := rows[x].result, rows[y].result
		switch mode {
		case sortByHost:
			if a.Host != b.Host {
				return a.Host < b.Host
			}
		case sortByExpiry:
			// Lo inalcanzable primero: es lo que hay que mirar ya.
			if a.HasCert() != b.HasCert() {
				return !a.HasCert()
			}
			if a.DaysLeft != b.DaysLeft {
				return a.DaysLeft < b.DaysLeft
			}
			if a.Host != b.Host {
				return a.Host < b.Host
			}
		default:
			if a.Group != b.Group {
				return a.Group < b.Group
			}
			if a.Host != b.Host {
				return a.Host < b.Host
			}
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.AF != b.AF {
			return a.AF < b.AF
		}
		return a.IPText() < b.IPText()
	})
}
