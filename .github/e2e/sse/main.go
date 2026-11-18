// Command sse is the streaming backend of the end-to-end test.
//
// It sends four Server-Sent Events two seconds apart and then closes the
// stream. The plugin's private response wrapper adds Cache-Control/Vary to
// protected responses; the e2e script compares the time of the first byte with
// the end of the stream to prove that the wrapper still flushes a response that
// has no Content-Length. A buffered response delivers headers and body together
// only when this handler returns, about six seconds after the first event was
// written.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	events := flag.Int("events", 4, "number of events to send")
	interval := flag.Duration("interval", 2*time.Second, "delay between events")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(rw http.ResponseWriter, req *http.Request) {
		flusher, ok := rw.(http.Flusher)
		if !ok {
			http.Error(rw, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		header := rw.Header()
		header.Set("Content-Type", "text/event-stream")
		header.Set("Cache-Control", "no-cache")
		header.Set("X-Accel-Buffering", "no")
		rw.WriteHeader(http.StatusOK)
		for i := 0; i < *events; i++ {
			if i > 0 {
				select {
				case <-req.Context().Done():
					return
				case <-time.After(*interval):
				}
			}
			fmt.Fprintf(rw, "data: event-%d\n\n", i)
			flusher.Flush()
		}
	})

	log.Fatal(http.ListenAndServe(*addr, mux))
}
