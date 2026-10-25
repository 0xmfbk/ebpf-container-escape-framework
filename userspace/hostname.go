package main

import (
	"os"
	"sync"
)

var (
	hostnameOnce sync.Once
	hostnameVal  string
)

func getHostname() (string, error) {
	var err error
	hostnameOnce.Do(func() {
		hostnameVal, err = os.Hostname()
		// Fallback assignment must happen inside the Once: writing
		// hostnameVal after Do returns was a data race.
		if hostnameVal == "" {
			hostnameVal = "unknown"
		}
	})
	return hostnameVal, err
}
