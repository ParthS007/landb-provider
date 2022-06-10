package commands

import (
    "net"

	// Logger
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var checkLandbCmd = &cobra.Command{
	Use:   "check-landb",
	Short: "check-landb",
	Long:  `check-landb`,
	Run: func(cmd *cobra.Command, args []string) {
	   if len(args) > 1{
		  log.Fatal("subcommand check-landb only take one argument")
	   }
	   err := CheckLandbRecord(args[0])
	   if err != true {
		  log.Fatal(err)
	   }
	},
}

// Method to check for matching `.cern.ch` domain names only.
func CheckLandbRecord(hostname string) (bool) {
	// Validate DNS is not attributed
	addrs, err := net.LookupHost(hostname)
	// If lookup finds no host it is an error, but in this case means hostname available
	if err != nil {
		log.Infof("The hostname %s is available and can be used.", hostname)
		return true
	}

	// If the hostname is in use, check if all the IPs belong to our cluster
	var clusterAddresses []string
	for _, node := range cluster.roleIngressNodes {
		for _, address := range node.Status.Addresses {
			clusterAddresses = append(clusterAddresses, address.Address)
		}
	}
	for _, addr := range addrs {
		// if the resolved IPs belong to our ingress nodes, allow Adding aliases
		if !Contains(clusterAddresses, addr) {
			log.Warningf("Landb-provider detected that the hostname is already atributed to out of cluster IP %s.", addr)
			return false
		}
	}
	log.Debug("All IP addresses obtained for the hostname are registered to this cluster.")
	return true
}

// Contains will find if substring exists in []string
func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
