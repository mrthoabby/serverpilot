package main

import (
	"github.com/mercadolibre/serverpilot/cmd"
)

func main() {
	cmd.SetVersion(Version)
	cmd.Execute()
}
