package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLIArguments(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{{nil, 2}, {[]string{"--help"}, 0}, {[]string{"sync", "--help"}, 0}, {[]string{"invalid"}, 2}, {[]string{"sync", "--credential=sensitive-value"}, 2}, {[]string{"sync", "--config", "/nonexistent/config.yaml"}, 2}} {
		var b bytes.Buffer
		if code := run(context.Background(), tc.args, &b); code != tc.code {
			t.Errorf("code %d, wanted %d", code, tc.code)
		}
		if strings.Contains(b.String(), "sensitive-value") {
			t.Fatal("leaked argument")
		}
	}
}
