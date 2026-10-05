// Package safe keeps a panic in one goroutine from taking down the whole process.
package safe

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"
)

// restartDelay is how long Loop waits before running its func again after a panic, so a func that always panics doesn't spin.
const restartDelay = time.Second

// Panic is a recovered panic, with the stack of the goroutine where it happened.
type Panic struct {
	Value any
	Stack []byte
}

func (p *Panic) Error() string { return fmt.Sprintf("panic: %v", p.Value) }

// Recover, when deferred, hands a panic in the deferring goroutine to handle as a *Panic and lets the goroutine go on unwinding.
func Recover(handle func(error)) {
	if r := recover(); r != nil {
		handle(&Panic{Value: r, Stack: debug.Stack()})
	}
}

// Loop runs f until it returns or ctx ends; a panic in f is logged and f runs again after restartDelay.
func Loop(ctx context.Context, log *slog.Logger, name string, f func(context.Context)) {
	for {
		var p *Panic
		func() {
			defer Recover(func(err error) { p = err.(*Panic) })
			f(ctx)
		}()
		if p == nil {
			return
		}
		log.Error("panic; running it again", "loop", name, "panic", p.Value, "stack", string(p.Stack))
		select {
		case <-ctx.Done():
			return
		case <-time.After(restartDelay):
		}
	}
}
