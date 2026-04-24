package main

import (
	"github.com/mrthoabby/serverpilot/cmd"
)

func main() {
	cmd.SetVersion(Version)
	cmd.Execute()
}
