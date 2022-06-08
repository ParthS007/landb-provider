package commands

import (
	"crypto/tls"
	"fmt"
    "net"
    "net/http"
	"sync"
	"time"

	"gopkg.in/gcfg.v1"

	// Logger
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	//// OpenStack
	// Authentication
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"

	//// Kubernetes
	v1Type "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netutil "k8s.io/apimachinery/pkg/util/net"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/apimachinery/pkg/types"
)

// LandbProvider stores the OS and Kubernetes conn handles and options
type LandbProvider struct {
	// LandbAliasEnabled defines if landb-provider should manage registration of alias
	LandbAliasEnabled bool
	// NumIngressNodes is the number of ingress instances to be kept active
	NumIngressNodes int
	// Allow ingress to be created if the existent landb-alias references self
	ServerBypassCernDNS bool

	// CloudConfig is the location of the openstack cloud config
	CloudConfig  string
	config       *rest.Config
	clientset    *kubernetes.Clientset
	osProvider   *gophercloud.ProviderClient
	serverClient *gophercloud.ServiceClient
}

var checkLandbCmd = &cobra.Command{
	Use:   "check-landb",
	Short: "check-landb",
	Long:  `check-landb`,
	Run: func(cmd *cobra.Command, args []string) {
	   if len(args) > 1{
		  log.Fatal("subcommand check-landb only take one argument")
	   }
	   err := checkLandb(args)
	   if err != nil {
		  log.Fatal(err)
	   }
	},
}

// Init sets all the required clients to talk to openstack
func (d *LandbProvider) Init() {
	// init Lock
	cluster.mutex = &sync.Mutex{}

	// ////////////////////////////////// K8s Config
	// get K8s config
	var err error
	d.config, err = rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Could not get Kubernetes configuration options: %v", err)
	}
	// creates the clientset
	d.clientset, err = kubernetes.NewForConfig(d.config)
	if err != nil {
		log.Fatalf("Could not create the client set to comunicate with the Kubernetes engine: %v", err)
	}

	// ////////////////////////////////// OS Config
	// HACK: This package (Config) comes from providerOpenStack.go to fix
	// 				the apimachinery dependencies headache
	var cfg Config
	if err := gcfg.ReadFileInto(&cfg, d.CloudConfig); err != nil {
		log.Fatalf("Could not get OpenStack configuration file: %v", err)
	}

	// HACK: This package (toAuthOptsExt) comes from providerOpenStack.go to fix
	// 				the apimachinery dependencies headache
	authOpts := toAuthOptsExt(cfg)

	d.osProvider, err = openstack.NewClient(cfg.Global.AuthURL)
	if err != nil {
		log.Fatalf("Could not authenticate client: %v", err)
	}

	if cfg.Global.CAFile != "" {
		roots, err := certutil.NewPool(cfg.Global.CAFile)
		if err != nil {
			log.Fatalf("Could not create new Certificate Pool: %v", err)
		}
		config := &tls.Config{}
		config.RootCAs = roots
		d.osProvider.HTTPClient.Transport = netutil.SetOldTransportDefaults(&http.Transport{TLSClientConfig: config})

	}

	userAgent := gophercloud.UserAgent{}
	userAgent.Prepend(fmt.Sprintf("landb-provider/unreleased"))
	log.Infof("user-agent: %s", userAgent.Join())
	d.osProvider.UserAgent = userAgent

	err = openstack.AuthenticateV3(d.osProvider, authOpts, gophercloud.EndpointOpts{})
	if err != nil {
		log.Fatalf("Could not authenticate: %v", err)
	}

	d.serverClient, err = openstack.NewComputeV2(d.osProvider, gophercloud.EndpointOpts{Region: cfg.Global.Region})
	if err != nil {
		log.Fatalf("Could not get client for the to interact with Server API: %v", err)
	}
}


// Method to check for matching `.cern.ch` domain names only.
func checkLandbRecord(hostname string) ([]string, bool) {
	// Validate DNS is not attributed
	addrs, err := net.LookupHost(hostname)
	// If lookup finds no host it is an error, but in this case means hostname available
	if err != nil {
		log.Infof("The hostname %s is available and can be used.", hostname)
		return addrs, true
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
			return addrs, false
		}
	}
	log.Debug("All IP addresses obtained for the hostname are registered to this cluster.")
	return addrs, true
}


// Method to update/delete the Landb alias
func (d *LandbProvider) UpdateLandbAlias(cluster *stateData, kubernetesAliases []string, kubernetesDeletedAliases []string) error {
    if len(cluster.roleIngressNodes) == 0 {
		log.Info("There are no available ingress nodes on the cluster where to add/del landb-alias. Nothing to do.")
		return nil
	}

	// Lets get all the defined Nodes UUIDs
	var uuids []string
	for _, node := range cluster.roleIngressNodes {
		uuids = append(uuids, node.Status.NodeInfo.SystemUUID)
	}
	// Get all the current Openstack landb-alias for each of the role ingress servers
	nodesCurrentMetadatum, err := d.GetOpenstackPropertyByNodeUUID("landb-alias", uuids)
	if err != nil {
		return fmt.Errorf("error getting OS nodes properties: %v", err)
	}

	// For each Node with role Ingress
	for i, node := range cluster.roleIngressNodes {
		postfix := fmt.Sprintf("--load-%d-", i+1)
		// kubernetesAliases
		nodeCurrentAliasesString := nodesCurrentMetadatum[i]["landb-alias"]
		kubernetesModifiedAliases := append(kubernetesAliases, kubernetesDeletedAliases...)
		// If no alias to add or delete, there are only user aliases. Skip...
		if len(kubernetesModifiedAliases) == 0 {
			continue
		}
		nodeCurrentAliases := strings.Split(nodeCurrentAliasesString, ",")
		// UserDefinedAlias = NodeCurrentAliases - kubernetesModifiedAliases
		nodeUserDefinedAliases := ExtractUserDefinedAliasesFromNode(nodeCurrentAliases, kubernetesModifiedAliases)
		log.Infof("Configuring user defined aliases on node %s: %v", node.Name, nodeUserDefinedAliases)
		log.Infof("Configuring kubernetes defined aliases on node %s: %v", node.Name, kubernetesAliases)

		// Get the aliases string that will be commited to the node
		nodeNewAliases := append(kubernetesAliases, nodeUserDefinedAliases...)
		nodeNewAliasesString := GenerateFQDNAliasString(nodeNewAliases, postfix)
		// If the resulting string is an empty string, we delete the landb-alias key from the Openstack node
		if len(nodeNewAliasesString) == 0 {
			log.Debugf("Removing landb-alias property from node %s as there are no current defined alias", node.Name)
			err = d.DeleteOpenstackPropertyByNodeUUID("landb-alias", node.Status.NodeInfo.SystemUUID)
			if err != nil {
				log.Warningf("Error deleting metadata.landb-alias from node %s: %v", node.Name, err)
				return
			}
			continue
		}

		// Next node if there is no need to submit aliasesString as they are the same
		if strings.Compare(nodeNewAliasesString, nodeCurrentAliasesString) == 0 {
			log.Debugf("Skiping node %s as there are no new modifications", node.Name)
			// If the landbAliasString is the same the server dosen't need update, skip
			continue
		}
		// If this server needs changing, and fqdn exist in other nodes returned by
		// osMetadatum, the landb-alias has to be deleted before as not doing this creates a conflict
		for iOS, iMetadatum := range nodesCurrentMetadatum {
			// Skip older nodes because they where updated already
			if iOS < i {
				continue
			}
			otherNodesAliases := strings.Split(iMetadatum["landb-alias"], ",")
			// For each alias to be added, guarantee that it does not exist elsewhere
			// if kubernetesAliases+postfix exist in other nodes, we need to first remove it
			for _, nodeNewAlias := range strings.Split(nodeNewAliasesString, ",") {
				if Contains(otherNodesAliases, nodeNewAlias) {
					err := d.DeleteOpenstackPropertyByNodeUUID("landb-alias", cluster.roleIngressNodes[iOS].Status.NodeInfo.SystemUUID)
					if err != nil {
						log.Errorf("Error deleting metadata from server id %s: %v", node.Status.NodeInfo.SystemUUID, err)
					}
					nodesCurrentMetadatum[iOS] = map[string]string{"landb-alias": ""}
					break
				}
			}
		}
		// We can now add the alias
		err = d.SetOpenstackPropertyByNodeUUID(cluster, "landb-alias", nodeNewAliasesString, node.Status.NodeInfo.SystemUUID)
		if err != nil {
			log.Errorf("Error adding alias list %v on server %s: %v", kubernetesAliases, node.Status.NodeInfo.SystemUUID, err)
		}
	}
	// Update status of configured alias
	cluster.aliases = kubernetesAliases

	log.Infof("Current aliases on ingress nodes: %v", cluster.aliases)
	return nil
}


// ExtractUserDefinedAliasesFromNode will get all the user defined aliases from the node
func ExtractUserDefinedAliasesFromNode(nodeCurrentAliases []string, clusterDefinedAliases []string) (userAliases []string) {
	if len(nodeCurrentAliases) == 0 {
		return []string{}
	}

	matched := false
	for _, currentAlias := range nodeCurrentAliases {
		for _, hostname := range clusterDefinedAliases {
			re := regexp.MustCompile("^" + hostname + `(--load-)(\d)+-`)
			if result := re.MatchString(currentAlias); result {
				matched = true
				break
			}
		}
		if !matched {
			userAliases = append(userAliases, currentAlias)
		}
		matched = false
	}
	return RemoveDuplicatesFromSlice(userAliases)
}


// GenerateFQDNAliasString will append and then concatenate the hostnames for landb commit
func GenerateFQDNAliasString(aliases []string, postfix string) string {
	var fqdn []string
	re := regexp.MustCompile(`(--load-)(\d)+-`)
	for _, alias := range aliases {
		if len(alias) == 0 {
			continue
		}
		// This is one of the user defined alias, lets add it without appending load
		if matched := re.MatchString(alias); matched {
			fqdn = append(fqdn, alias)
			continue
		}
		fqdn = append(fqdn, alias+postfix)
	}
	// set metadatum options to openstack server
	fqdn = RemoveDuplicatesFromSlice(fqdn)
	sort.Strings(fqdn)
	return strings.Join(fqdn, ",")
}

// SetOpenstackPropertyByNodeUUID sets the metadata property:value on the
// server uuid
func (d *LandbProvider) SetOpenstackPropertyByNodeUUID(cluster *stateData, property string, value string, nodeUUID string) (err error) {
	repeat := 0
	for {
		opts := servers.MetadatumOpts{property: value}
		_, err = servers.CreateMetadatum(d.serverClient, nodeUUID, opts).Extract()
		if err != nil {
			repeat++
			if repeat > 5 {
				return fmt.Errorf("landb-provider cannot persist property %s with value %s in node %s: %v", property, value, nodeUUID, err)
			}
			time.Sleep(2 * time.Second)
		} else {
			log.Infof("successfully upserted %s=%s on node %s.", property, value, nodeUUID)
			break
		}
	}
	return nil
}

// DeleteOpenstackPropertyByNodeUUID will delete the property from the node metadata using node uuid
func (d *LandbProvider) DeleteOpenstackPropertyByNodeUUID(property string, nodeUUID string) (err error) {
	repeat := 0
	for {
		err = servers.DeleteMetadatum(d.serverClient, nodeUUID, property).ExtractErr()
		if err != nil {
			repeat++
			if repeat > 5 {
				return fmt.Errorf("could not delete metadata.%s from node %s: %v", property, nodeUUID, err)
			}
			time.Sleep(2 * time.Second)
		} else {
			log.Infof("successfully dropped property %s from node %s.", property, nodeUUID)
			break
		}
	}
	return nil
}

// GetOpenstackPropertyByNodeUUID will get OS data from the nodesUUID list and return a Metadatum object list in the same order
func (d *LandbProvider) GetOpenstackPropertyByNodeUUID(property string, nodesUUID []string) (serversMetadatum []map[string]string, err error) {
	for _, uuid := range nodesUUID {
		keyValue, err := servers.Metadatum(d.serverClient, uuid, property).Extract()
		if err != nil {
			if err, ok := err.(gophercloud.ErrDefault404); ok {
				keyValue = map[string]string{property: ""}
			} else {
				return nil, fmt.Errorf("could not retrieve node %s metadatum for property %s: %s", uuid, property, err)
			}
		}
		log.Debugf("got property %v from node uuid %s", keyValue, uuid)
		serversMetadatum = append(serversMetadatum, keyValue)
	}
	return serversMetadatum, nil
}
