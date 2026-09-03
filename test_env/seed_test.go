package main

import (
	"strings"
	"testing"
)

// yq must produce a double-quoted YAML scalar that survives ':', '#', quotes and backslashes,
// so config values cannot break (or silently alter) the cloud-init documents.
func TestYq(t *testing.T) {
	cases := map[string]string{
		`live`:        `"live"`,
		`a:b #c`:      `"a:b #c"`,
		`say "hi"`:    `"say \"hi\""`,
		`back\slash`:  `"back\\slash"`,
		``:            `""`,
	}
	for in, want := range cases {
		if got := yq(in); got != want {
			t.Errorf("yq(%q) = %s, want %s", in, got, want)
		}
	}
}

// A hostile password must appear quoted in the rendered user-data, never as a bare scalar.
func TestRenderUserDataQuotesValues(t *testing.T) {
	c := DefaultConfig()
	c.VM.Password = `p:a#s"s`
	c.VM.Hostname = `host:name`
	out := renderUserData(c, []byte("x"))
	if !strings.Contains(out, `plain_text_passwd: "p:a#s\"s"`) {
		t.Errorf("password not quoted/escaped in user-data:\n%s", out)
	}
	if !strings.Contains(out, `hostname: "host:name"`) {
		t.Errorf("hostname not quoted in user-data")
	}
}
