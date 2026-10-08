// Package measurement provides optional one-operation measurements without a benchmark harness.
package measurement

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

// Start returns a function to print elapsed time and Go heap counters to stderr.
// HeapDelta is signed; Alloc is a snapshot, not peak memory or process RSS.
func Start(enabled bool, label string) func() {
	if !enabled {
		return func() {}
	}
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	return func() {
		elapsed := time.Since(started)
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		fmt.Fprintf(os.Stderr, "Medición [%s]: tiempo=%s | asignados=%d bytes | heap_actual=%d bytes | delta_heap=%d bytes | GC=%d\n", label, elapsed, after.TotalAlloc-before.TotalAlloc, after.Alloc, int64(after.Alloc)-int64(before.Alloc), after.NumGC-before.NumGC)
	}
}
