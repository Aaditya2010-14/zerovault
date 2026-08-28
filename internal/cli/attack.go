package cli

import (
	"flag"
	"os"

	"zerovault/attacks"
)

func cmdAttack(args []string) int {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	fs.Parse(args)

	report, err := attacks.RunAll(os.Stdout)
	if err != nil {
		printError("%v", err)
		return 1
	}
	for _, r := range report.Results {
		if r.Result.Status == attacks.StatusVulnerable {
			return 1
		}
	}
	return 0
}
