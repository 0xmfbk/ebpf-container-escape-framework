package main

import "bytes"

type jsonEncoder struct{}

func (jsonEncoder) Name() string        { return "json" }
func (jsonEncoder) ContentType() string { return "application/json" }

func (jsonEncoder) Encode(a *SecurityAlert) ([]byte, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	writeAlertJSON(buf, a)

	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}
