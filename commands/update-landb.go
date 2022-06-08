package commands

import (
	"fmt"
	"time"
	"strings"
	"regexp"
	"sort"

	// Logger
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	//// OpenStack Authentication
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
)

var updateLandbCmd = &cobra.Command{
	Use:   "update-landb",
	Short: "update-landb",
	Long:  `update-landb`,
	Run: func(cmd *cobra.Command, args []string) {
		var clusterData *stateData
		var kubernetesAliases []string
		var kubernetesDeletedAliases []string
	   	err := UpdateLandbRecord(clusterData, kubernetesAliases, kubernetesDeletedAliases)
	   	if err != nil {
			log.Fatal(err)
		}
	},
}


// Method to update/delete the Landb alias
func UpdateLandbRecord(cluster *stateData, kubernetesAliases []string, kubernetesDeletedAliases []string) error {
	var d *LandbProvider
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
				return err
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

// RemoveDuplicatesFromSlice Deduplicates strings on a slice
func RemoveDuplicatesFromSlice(s []string) []string {
	m := make(map[string]bool)
	for _, item := range s {
		m[item] = true
	}

	var result []string
	for item := range m {
		result = append(result, item)
	}
	return result
}