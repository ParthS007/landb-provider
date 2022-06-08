package commands

import (
	"crypto/tls"
	"fmt"
    "net"
    "net/http"
	"sync"

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
    "github.com/gophercloud/gophercloud/openstack/identity/v3/extensions/trusts"

	//// Kubernetes
	v1Type "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	netutil "k8s.io/apimachinery/pkg/util/net"
	certutil "k8s.io/client-go/util/cert"
)

// LandbProvider stores the OS and Kubernetes conn handles and options
type LandbProvider struct {
	// NumIngressNodes is the number of ingress instances to be kept active
	NumIngressNodes int

	// CloudConfig is the location of the openstack cloud config
	CloudConfig  string
	config       *rest.Config
	clientset    *kubernetes.Clientset
	osProvider   *gophercloud.ProviderClient
	serverClient *gophercloud.ServiceClient
}

type stateData struct {
	// Lock
	mutex *sync.Mutex
	// Kubernetes
	roleIngressNodes    []v1Type.Node
	notRoleIngressNodes []v1Type.Node
	ingresses           []networking.Ingress
	oldIngresses        []networking.Ingress

	// Defined aliases (only hostname)
	aliases []string
}

// Config is used to read and store information from the cloud configuration file
type Config struct {
	Global struct {
		AuthURL         string `gcfg:"auth-url"`
		Username        string
		UserID          string `gcfg:"user-id"`
		Password        string
		TenantID        string `gcfg:"tenant-id"`
		TenantName      string `gcfg:"tenant-name"`
		TrustID         string `gcfg:"trust-id"`
		DomainID        string `gcfg:"domain-id"`
		DomainName      string `gcfg:"domain-name"`
		Region          string
		CAFile          string `gcfg:"ca-file"`
		SecretName      string `gcfg:"secret-name"`
		SecretNamespace string `gcfg:"secret-namespace"`
		KubeconfigPath  string `gcfg:"kubeconfig-path"`
	}
}

func toAuthOptsExt(cfg Config) trusts.AuthOptsExt {
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: cfg.Global.AuthURL,
		Username:         cfg.Global.Username,
		UserID:           cfg.Global.UserID,
		Password:         cfg.Global.Password,
		TenantID:         cfg.Global.TenantID,
		TenantName:       cfg.Global.TenantName,
		DomainID:         cfg.Global.DomainID,
		DomainName:       cfg.Global.DomainName,

		// Persistent service, so we need to be able to renew tokens.
		AllowReauth: true,
	}

	return trusts.AuthOptsExt{
		TrustID:            cfg.Global.TrustID,
		AuthOptionsBuilder: &opts,
	}
}

var cluster stateData

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

// Contains will find if substring exists in []string
func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
