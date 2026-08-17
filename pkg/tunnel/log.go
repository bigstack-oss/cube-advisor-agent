package tunnel

import (
	"io"
	"log"
)

// discardLogger silences the multiplexer's internal logging. Session lifecycle
// is logged by the caller, which knows the cluster identity that makes a line
// worth reading.
func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
