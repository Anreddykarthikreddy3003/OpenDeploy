// Command opendeployctl is the OpenDeploy CLI.
package main

import (
	"os"

	"github.com/anreddykarthikreddy3003/opendeploy/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
