package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// jobCmd is `cube-advisor-agent job <subcommand>`. The Advisor runs `job
// start` through the recorded shell, after an admin approved the command;
// an operator can list and stop jobs here.
func jobCmd(args []string) int {
	if len(args) < 1 {
		jobUsage()
		return exitUsage
	}
	fs := flag.NewFlagSet("job "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", toolplane.DefaultJobsDir, "where jobs are kept")
	id := fs.String("id", "", "the job id")
	deadline := fs.String("deadline", "", "when the job is stopped, RFC 3339")
	cmdB64 := fs.String("command-b64", "", "the command, base64")
	all := fs.Bool("all", false, "stop every running job")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if *id == "" && fs.NArg() > 0 {
		*id = fs.Arg(0)
	}
	j := &toolplane.Jobs{Dir: *dir}
	switch args[0] {
	case "start":
		dl, err := time.Parse(time.RFC3339, *deadline)
		if err != nil {
			fmt.Fprintf(os.Stderr, "job start: -deadline: %v\n", err)
			return exitUsage
		}
		command, err := base64.StdEncoding.DecodeString(*cmdB64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "job start: -command-b64: %v\n", err)
			return exitUsage
		}
		return printJob(j.Start(*id, string(command), dl))
	case "status":
		return printJob(j.Status(*id, toolplane.DefaultJobLines))
	case "stop":
		if *all {
			code := exitOK
			for _, st := range j.List() {
				if !st.Terminal() {
					if printJob(j.Stop(st.ID)) != exitOK {
						code = exitFailed
					}
				}
			}
			return code
		}
		return printJob(j.Stop(*id))
	case "list":
		out := json.NewEncoder(os.Stdout)
		for _, st := range j.List() {
			_ = out.Encode(st)
		}
		return exitOK
	default:
		jobUsage()
		return exitUsage
	}
}

func printJob(st any, err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "job: %v\n", err)
		return exitFailed
	}
	_ = json.NewEncoder(os.Stdout).Encode(st)
	return exitOK
}

func jobUsage() {
	fmt.Fprintf(os.Stderr, `cube-advisor-agent job

  start  -id <id> -deadline <RFC 3339> -command-b64 <base64>
  status <id>
  stop   <id> | -all
  list
`)
}
