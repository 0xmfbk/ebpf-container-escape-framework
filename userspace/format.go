package main

import "fmt"

// Encoder turns a SecurityAlert into the wire payload for the chosen format.
// The returned slice has NO trailing newline; the transport decides framing.
type Encoder interface {
	Encode(a *SecurityAlert) ([]byte, error)
	Name() string
	ContentType() string
}

func newEncoder(format string) (Encoder, error) {
	switch format {
	case "", "json":
		return jsonEncoder{}, nil
	case "ecs":
		return ecsEncoder{}, nil
	case "ocsf":
		return ocsfEncoder{}, nil
	case "cef":
		return cefEncoder{}, nil
	case "leef":
		return leefEncoder{}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q (want json|ecs|ocsf|cef|leef)", format)
	}
}
