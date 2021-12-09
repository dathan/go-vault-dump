package dump

import (
	"errors"
	"log"
	"os"
)

type output struct {
	path     string
	encoding string
	kind     string // cant use type,reserved word
}

// NewOutput returns an output type unless there is a validation error where
// it returns an error instead
func NewOutput(p, e, k string) (*output, error) {
	c := &output{}
	if !c.setPath(p) {
		return &output{}, errors.New("failed to set output path")
	}
	if !c.setEncoding(e) {
		return &output{}, errors.New("failed to set output encoding")
	}
	if !c.setKind(k) {
		return &output{}, errors.New("failed to set output kind")
	}
	return c, nil
}

func (o *output) setPath(s string) bool {
	o.path = s
	return true
}
func (o *output) setEncoding(s string) bool {
	expectedEncodings := []string{"json", "yaml"}
	for _, e := range expectedEncodings {
		if s == e {
			o.encoding = s
			return true
		}
	}

	log.SetOutput(os.Stderr)
	log.Printf("Unexpected encoding %s, we only accept: %v", s, expectedEncodings)
	return false
}
func (o *output) setKind(s string) bool {
	expectedKinds := []string{"file", "stdout", "s3"}
	for _, k := range expectedKinds {
		if s == k {
			o.kind = s
			return true
		}
	}

	log.SetOutput(os.Stderr)
	log.Printf("Unexpected output type %s\n", s)
	return false
}

func (o *output) GetPath() string {
	return o.path
}
func (o *output) GetEncoding() string {
	return o.encoding
}
func (o *output) GetKind() string {
	return o.kind
}
