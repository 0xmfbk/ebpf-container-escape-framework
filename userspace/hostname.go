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
	})
	if hostnameVal == "" {
		hostnameVal = "unknown"
	}
	return hostnameVal, err
}
