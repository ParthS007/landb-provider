package commands

import (
   // Logger
   log "github.com/sirupsen/logrus"

   "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
   Use:   "landb-provider",
   Short: "landb-provider",
   Long: `landb-provider`,
}

/*
The init function is responsible to run things
which we will require before anything else
say 
  - Fetch API Keys
  - Set Logging level
  - Setup any environment variable required for the app
*/

func init() {
   rootCmd.AddCommand(checkLandbCmd, updateLandbCmd)
}

func Execute() {
   if err := rootCmd.Execute(); err != nil {
      log.Fatal(err)
   }
}
