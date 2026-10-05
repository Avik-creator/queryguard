package safe

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestRecoverHandsOnAPanicWithItsStack(t *testing.T) {
	var got error
	func() {
		defer Recover(func(err error) { got = err })
		panic("bug")
	}()

	p, ok := errors.AsType[*Panic](got)
	if !ok || p.Value != "bug" || !strings.Contains(string(p.Stack), "TestRecoverHandsOnAPanicWithItsStack") {
		t.Fatalf("got %v; want a *Panic with the value and the stack where it happened", got)
	}
}

func TestRecoverDoesNothingWithoutAPanic(t *testing.T) {
	called := false
	func() {
		defer Recover(func(error) { called = true })
	}()

	if called {
		t.Error("handle was called without a panic")
	}
}

func TestLoopRunsAgainAfterAPanicUntilItsContextEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		ctx, cancel := context.WithCancel(t.Context())
		runs := 0
		done := make(chan struct{})
		go func() {
			defer close(done)
			Loop(ctx, slog.New(slog.NewTextHandler(&logs, nil)), "monitor", func(ctx context.Context) {
				runs++
				if runs < 3 {
					panic("bug")
				}
				<-ctx.Done()
			})
		}()

		time.Sleep(10 * time.Second)
		cancel()
		<-done

		if runs != 3 {
			t.Errorf("f ran %d times; want 3, twice panicking", runs)
		}
		if n := strings.Count(logs.String(), "loop=monitor"); n != 2 {
			t.Errorf("logged %d panics; want 2:\n%s", n, logs.String())
		}
	})
}

func TestLoopStopsWhenItsFuncReturns(t *testing.T) {
	runs := 0
	Loop(t.Context(), slog.New(slog.DiscardHandler), "once", func(context.Context) { runs++ })

	if runs != 1 {
		t.Errorf("f ran %d times; want once", runs)
	}
}
