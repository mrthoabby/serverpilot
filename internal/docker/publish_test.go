package docker

import (
	"reflect"
	"testing"
)

func TestInsertPublishPort(t *testing.T) {
	args := []string{"docker", "run", "-d", "--name", "app", "image:tag"}
	got := insertPublishPort(args, "127.0.0.1:3000:8080/tcp")
	want := []string{"docker", "run", "-p", "127.0.0.1:3000:8080/tcp", "-d", "--name", "app", "image:tag"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("insertPublishPort() = %#v, want %#v", got, want)
	}
}
