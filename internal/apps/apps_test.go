package apps

import (
	"reflect"
	"testing"
)

func TestParseEnvContent(t *testing.T) {
	got, err := ParseEnvContent(`
# ignored
PORT=8080
 export API_URL="https://example.test"
TOKEN='secret value'
EMPTY=
`)
	if err != nil {
		t.Fatalf("ParseEnvContent returned error: %v", err)
	}
	want := []string{
		"PORT=8080",
		"API_URL=https://example.test",
		"TOKEN=secret value",
		"EMPTY=",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseEnvContent mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseEnvContentRejectsInvalidLines(t *testing.T) {
	tests := []string{
		"NO_EQUALS",
		"BAD-NAME=value",
		"1BAD=value",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseEnvContent(input); err == nil {
				t.Fatal("ParseEnvContent accepted invalid env content")
			}
		})
	}
}
