// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calc

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	cresources "github.com/projectcalico/libcalico-go/lib/resources"
	"github.com/projectcalico/libcalico-go/lib/set"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
)

// L3RouteResolver is responsible for indexing (currently only IPv4 versions of):
//
// - IPAM blocks
// - IP pools
// - Node metadata (either from the Node resource, if available, or from HostIP)
//
// and emitting a set of longest prefix match routes that include:
//
// - The relevant destination CIDR.
// - The IP pool type that contains the CIDR (or none).
// - Other metadata about the containing IP pool.
// - Whether this (/32) CIDR is a host or not.
// - For workload CIDRs, the IP and name of the host that contains the workload.
//
// The BPF dataplane use the above to form a map of IP space so it can look up whether a particular
// IP belongs to a workload/host/IP pool etc. and where to forward that IP to if it needs to.
// The VXLAN dataplane combines routes for remote workloads with VTEPs from the VXLANResolver to
// form VXLAN routes.
type L3RouteResolver struct {
	myNodeName string
	callbacks  routeCallbacks

	trie   *IPv6RouteTrie
	trieV4 *IPv4RouteTrie

	// Store node metadata indexed by node name, and routes by the
	// block that contributed them.
	nodeNameToNodeInfo     map[string]l3rrNodeInfo
	blockToRoutes          map[string]set.Set
	nodeRoutes             nodeIPv6Routes
	nodeIPv4Routes         nodeIPv4Routes
	allPools               map[string]model.IPPool
	workloadIDToIPv4CIDRs  map[model.WorkloadEndpointKey][]cnet.IPNet
	workloadIDToIPv6CIDRs  map[model.WorkloadEndpointKey][]cnet.IPNet
	useNodeResourceUpdates bool
	routeSource            string
}

type l3rrNodeInfo struct {
	IPv4Addr ip.V4Addr
	IPv4CIDR ip.V4CIDR
	IPv6Addr ip.V6Addr
	IPv6CIDR ip.V6CIDR

	// Tunnel IP addresses
	IPIPAddr      ip.Addr
	VXLANIPv4Addr ip.Addr
	VXLANAddr     ip.Addr
	WireguardAddr ip.Addr

	Addresses []ip.Addr
}

func (i l3rrNodeInfo) Equal(b l3rrNodeInfo) bool {
	if i.IPv4Addr == b.IPv4Addr &&
		i.IPv4CIDR == b.IPv4CIDR &&
		i.IPIPAddr == b.IPIPAddr &&
		i.VXLANAddr == b.VXLANAddr &&
		i.VXLANIPv4Addr == b.VXLANIPv4Addr &&
		i.WireguardAddr == b.WireguardAddr {

		if len(i.Addresses) != len(b.Addresses) {
			return false
		}

		// We expect a small single number of addresses in single digits and
		// mostly in the same order.
		l := len(i.Addresses)
		for ia, a := range i.Addresses {
			found := false
			for j := 0; j < l; j++ {
				if a == b.Addresses[(ia+j)%l] {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

		return true
	}

	return false
}

func (i l3rrNodeInfo) AddrAsCIDR() ip.CIDR {
	return i.IPv6Addr.AsCIDR().(ip.CIDR)
}

func (i l3rrNodeInfo) AddresesV6AsCIDRs() []ip.V6CIDR {
	addrs := make(map[ip.Addr]struct{})

	addrs[i.IPv6Addr] = struct{}{}

	for _, a := range i.Addresses {
		if a.Version() == 4 {
			continue
		} else {
			addrs[a.(ip.V6Addr)] = struct{}{}
		}
	}

	cidrs := make([]ip.V6CIDR, len(addrs))
	idx := 0
	for a := range addrs {
		cidrs[idx] = a.AsCIDR().(ip.V6CIDR)
		idx++
	}

	return cidrs
}

func (i l3rrNodeInfo) AddresesV4AsCIDRs() []ip.V4CIDR {
	addrs := make(map[ip.Addr]struct{})

	addrs[i.IPv4Addr] = struct{}{}

	for _, a := range i.Addresses {
		if a.Version() == 4 {
			addrs[a.(ip.V4Addr)] = struct{}{}
		} else {
			continue
		}
	}

	cidrs := make([]ip.V4CIDR, len(addrs))
	idx := 0
	for a := range addrs {
		cidrs[idx] = a.AsCIDR().(ip.V4CIDR)
		idx++
	}

	return cidrs
}

func NewL3RouteResolver(hostname string, callbacks PipelineCallbacks, useNodeResourceUpdates bool, routeSource string) *L3RouteResolver {
	logrus.Info("Creating L3 route resolver")
	return &L3RouteResolver{
		myNodeName: hostname,
		callbacks:  callbacks,

		trie:   NewIPv6RouteTrie(),
		trieV4: NewIPv4RouteTrie(),

		nodeNameToNodeInfo:     map[string]l3rrNodeInfo{},
		blockToRoutes:          map[string]set.Set{},
		allPools:               map[string]model.IPPool{},
		workloadIDToIPv4CIDRs:  map[model.WorkloadEndpointKey][]cnet.IPNet{},
		workloadIDToIPv6CIDRs:  map[model.WorkloadEndpointKey][]cnet.IPNet{},
		useNodeResourceUpdates: useNodeResourceUpdates,
		routeSource:            routeSource,
		nodeRoutes:             newNodeRoutes(),
	}
}

func (c *L3RouteResolver) RegisterWith(allUpdDispatcher, localDispatcher *dispatcher.Dispatcher) {
	if c.useNodeResourceUpdates {
		logrus.Info("Registering L3 route resolver (node resources on)")
		allUpdDispatcher.Register(model.ResourceKey{}, c.OnResourceUpdate)
	} else {
		logrus.Info("Registering L3 route resolver (node resources off)")
		allUpdDispatcher.Register(model.HostIPKey{}, c.OnHostIPUpdate)
	}

	allUpdDispatcher.Register(model.IPPoolKey{}, c.OnPoolUpdate)

	// Depending on if we're using workload endpoints for routing information, we may
	// need all WEPs, or only local WEPs.
	logrus.WithField("routeSource", c.routeSource).Info("Registering for L3 route updates")
	if c.routeSource == "WorkloadIPs" {
		// Driven off of workload IP addressess. Register for all WEP udpates.
		allUpdDispatcher.Register(model.WorkloadEndpointKey{}, c.OnWorkloadUpdate)
	} else {
		// Driven off of IPAM data. Register for blocks and local WEP updates.
		allUpdDispatcher.Register(model.BlockKey{}, c.OnBlockUpdate)
		localDispatcher.Register(model.WorkloadEndpointKey{}, c.OnWorkloadUpdate)
	}
}

func (c *L3RouteResolver) OnWorkloadUpdate(update api.Update) (_ bool) {
	var ipv4DeepEqual, ipv6DeepEqual bool

	defer func() {
		if ipv4DeepEqual {
			c.flushV4()
		}
		if ipv6DeepEqual{
			c.flush()
		}
	}()

	key := update.Key.(model.WorkloadEndpointKey)

	// Look up the (possibly nil) old CIDRs.
	oldIPv4CIDRs := c.workloadIDToIPv4CIDRs[key]
	oldIPv6CIDRs := c.workloadIDToIPv6CIDRs[key]

	// Get the new CIDRs (again, may be nil if this is a deletion).
	var newIPv4CIDRs, newIPv6CIDRs []cnet.IPNet
	if update.Value != nil {
		newWorkload := update.Value.(*model.WorkloadEndpoint)
		if len(newWorkload.IPv4Nets) != 0 {
			newIPv4CIDRs = newWorkload.IPv4Nets
			ipv4DeepEqual = reflect.DeepEqual(oldIPv4CIDRs, newIPv4CIDRs)
			logrus.WithField("workload", key).WithField("newIPv4CIDRs", newIPv4CIDRs).Debug("Workload update")
		}
		if len(newWorkload.IPv6Nets) != 0 {
			newIPv6CIDRs = newWorkload.IPv6Nets
			ipv6DeepEqual = reflect.DeepEqual(oldIPv6CIDRs, newIPv6CIDRs)
			logrus.WithField("workload", key).WithField("newIPv6CIDRs", newIPv6CIDRs).Debug("Workload update")
		}

	}

	if ipv4DeepEqual && ipv6DeepEqual {
		// No change, ignore.
		logrus.Debug("No change to CIDRs, ignore.")
		return
	}

	// Incref the new CIDRs.
	if ipv4DeepEqual {
		for _, newIPv4CIDR := range newIPv4CIDRs {
			cidr := ip.CIDRFromCalicoNet(newIPv4CIDR).(ip.V4CIDR)
			c.trieV4.AddRef(cidr, key.Hostname, RefTypeWEP)
			c.nodeIPv4Routes.Add(nodenameIPv4Route{key.Hostname, cidr})
		}

		// Decref the old.
		for _, oldIPv4CIDR := range oldIPv4CIDRs {
			cidr := ip.CIDRFromCalicoNet(oldIPv4CIDR).(ip.V4CIDR)
			c.trieV4.RemoveRef(cidr, key.Hostname, RefTypeWEP)
			c.nodeIPv4Routes.Remove(nodenameIPv4Route{key.Hostname, cidr})
		}
	}

	if ipv6DeepEqual {
		for _, newIPv6CIDR := range newIPv6CIDRs {
			cidr := ip.CIDRFromCalicoNet(newIPv6CIDR).(ip.V6CIDR)
			c.trie.AddRef(cidr, key.Hostname, RefTypeWEP)
			c.nodeRoutes.Add(nodenameIPv6Route{key.Hostname, cidr})
		}

		// Decref the old.
		for _, oldIPv6CIDR := range oldIPv6CIDRs {
			cidr := ip.CIDRFromCalicoNet(oldIPv6CIDR).(ip.V6CIDR)
			c.trie.RemoveRef(cidr, key.Hostname, RefTypeWEP)
			c.nodeRoutes.Remove(nodenameIPv6Route{key.Hostname, cidr})
		}
	}

	if len(newIPv4CIDRs) > 0 {
		// Only store an entry if there are some CIDRs.
		c.workloadIDToIPv4CIDRs[key] = newIPv4CIDRs
	} else {
		delete(c.workloadIDToIPv4CIDRs, key)
	}

	if len(newIPv6CIDRs) > 0 {
		// Only store an entry if there are some CIDRs.
		c.workloadIDToIPv6CIDRs[key] = newIPv6CIDRs
	} else {
		delete(c.workloadIDToIPv6CIDRs, key)
	}

	return
}

func (c *L3RouteResolver) OnBlockUpdate(update api.Update) (_ bool) {
	// Queue up a flush.
	var isIPv4, isIPv6 bool

	defer func() {
		if isIPv4 {
			c.flushV4()
		}
		if isIPv6{
			c.flush()
		}
	}()

	// Update the routes map based on the provided block update.
	key := update.Key.String()

	deletes := set.New()
	adds := set.New()
	if update.Value != nil {
		// Block has been created or updated.
		// We don't allow multiple blocks with the same CIDR, so no need to check
		// for duplicates here. Look at the routes contributed by this block and determine if we
		// need to send any updates.

		if update.Value.(*model.AllocationBlock).CIDR.Version() == 6 {
			isIPv6 = true
			newRoutes := c.v6RoutesFromBlock(update.Value.(*model.AllocationBlock))
			logrus.WithField("numRoutes", len(newRoutes)).Debug("IPAM block update")
			cachedRoutes, ok := c.blockToRoutes[key]
			if !ok {
				cachedRoutes = set.New()
				c.blockToRoutes[key] = cachedRoutes
			}

			// Now scan the old routes, looking for any that are no-longer associated with the block.
			// Remove no longer active routes from the cache and queue up deletions.
			cachedRoutes.Iter(func(item interface{}) error {
				r := item.(nodenameIPv6Route)

				// For each existing route which is no longer present, we need to delete it.
				// Note: since r.Key() only contains the destination, we need to check equality too in case
				// the gateway has changed.
				if newRoute, ok := newRoutes[r.Key()]; ok && newRoute == r {
					// Exists, and we want it to - nothing to do.
					return nil
				}

				// Current route is not in new set - we need to withdraw the route, and also
				// remove it from internal state.
				deletes.Add(r)
				logrus.WithField("route", r).Debug("Found stale route")
				return set.RemoveItem
			})

			// Now scan the new routes, looking for additions.  Cache them and queue up adds.
			for _, r := range newRoutes {
				logCxt := logrus.WithField("newRoute", r)
				if cachedRoutes.Contains(r) {
					logCxt.Debug("Desired route already exists, skip")
					continue
				}

				logrus.WithField("route", r).Debug("Found new route")
				cachedRoutes.Add(r)
				adds.Add(r)
			}

			// At this point we've determined the correct diff to perform based on the block update. Queue up
			// updates.
			deletes.Iter(func(item interface{}) error {
				nr := item.(nodenameIPv6Route)
				c.trie.RemoveBlockRoute(nr.dst)
				c.nodeRoutes.Remove(nr)
				return nil
			})
			adds.Iter(func(item interface{}) error {
				nr := item.(nodenameIPv6Route)
				c.trie.UpdateBlockRoute(nr.dst, nr.nodeName)
				c.nodeRoutes.Add(nr)
				return nil
			})
		} else {
			isIPv4 = true
			newRoutes := c.v4RoutesFromBlock(update.Value.(*model.AllocationBlock))
			logrus.WithField("numRoutes", len(newRoutes)).Debug("IPAM block update")
			cachedRoutes, ok := c.blockToRoutes[key]
			if !ok {
				cachedRoutes = set.New()
				c.blockToRoutes[key] = cachedRoutes
			}

			// Now scan the old routes, looking for any that are no-longer associated with the block.
			// Remove no longer active routes from the cache and queue up deletions.
			cachedRoutes.Iter(func(item interface{}) error {
				r := item.(nodenameIPv4Route)

				// For each existing route which is no longer present, we need to delete it.
				// Note: since r.Key() only contains the destination, we need to check equality too in case
				// the gateway has changed.
				if newRoute, ok := newRoutes[r.Key()]; ok && newRoute == r {
					// Exists, and we want it to - nothing to do.
					return nil
				}

				// Current route is not in new set - we need to withdraw the route, and also
				// remove it from internal state.
				deletes.Add(r)
				logrus.WithField("route", r).Debug("Found stale route")
				return set.RemoveItem
			})

			// Now scan the new routes, looking for additions.  Cache them and queue up adds.
			for _, r := range newRoutes {
				logCxt := logrus.WithField("newRoute", r)
				if cachedRoutes.Contains(r) {
					logCxt.Debug("Desired route already exists, skip")
					continue
				}

				logrus.WithField("route", r).Debug("Found new route")
				cachedRoutes.Add(r)
				adds.Add(r)
			}

			// At this point we've determined the correct diff to perform based on the block update. Queue up
			// updates.
			deletes.Iter(func(item interface{}) error {
				nr := item.(nodenameIPv4Route)
				c.trieV4.RemoveBlockRoute(nr.dst)
				c.nodeIPv4Routes.Remove(nr)
				return nil
			})
			adds.Iter(func(item interface{}) error {
				nr := item.(nodenameIPv4Route)
				c.trieV4.UpdateBlockRoute(nr.dst, nr.nodeName)
				c.nodeIPv4Routes.Add(nr)
				return nil
			})
		}

	} else {
		// Block has been deleted. Clean up routes that were contributed by this block.
		logrus.WithField("update", update).Debug("IPAM block deleted")
		routes := c.blockToRoutes[key]
		if routes != nil {
			routes.Iter(func(item interface{}) error {
				nr, existedV6Route := item.(nodenameIPv6Route)
				if existedV6Route {
					c.trie.RemoveBlockRoute(nr.dst)
				} else {
					nrV4 := item.(nodenameIPv4Route)
					c.trieV4.RemoveBlockRoute(nrV4.dst)
				}

				return nil
			})
		}
		delete(c.blockToRoutes, key)
	}
	return
}

func (c *L3RouteResolver) OnResourceUpdate(update api.Update) (_ bool) {
	var isIPv4, isIPv6 bool
	// We only care about nodes, not other resources.
	resourceKey := update.Key.(model.ResourceKey)
	if resourceKey.Kind != apiv3.KindNode {
		return
	}

	// Queue up a flush.
	defer func() {
		if isIPv4 {
			c.flushV4()
		}
		if isIPv6 {
			c.flush()
		}
	}()

	// Extract the nodename and check whether the node was known already.
	nodeName := update.Key.(model.ResourceKey).Name

	logCxt := logrus.WithField("node", nodeName).WithField("update", update)
	logCxt.Debug("OnResourceUpdate triggered")

	// Update our tracking data structures.
	var nodeInfo *l3rrNodeInfo

	if update.Value != nil {

		node := update.Value.(*apiv3.Node)

		if node.Spec.BGP != nil && node.Spec.BGP.IPv6Address != "" {
				isIPv6 = true
				bgp := node.Spec.BGP
				// Use cnet.ParseCIDROrIP so we get the IP and the CIDR.  The parse functions in the ip package
				// throw away one or the other.
				ipv6, caliNodeCIDR, err := cnet.ParseCIDROrIP(bgp.IPv6Address)
				if err != nil {
					logrus.WithError(err).Panic("Failed to parse already-validated IP address")
				}
				logrus.WithField("node bgp ipv6 address", ipv6).Info("newNodeInfo ")
				logrus.WithField("node bgp ipv6 cidr", caliNodeCIDR).Info("newNodeInfo ")
				nodeInfo = &l3rrNodeInfo{
					IPv6Addr: ip.FromCalicoIP(*ipv6).(ip.V6Addr),
					IPv6CIDR: ip.CIDRFromCalicoNet(*caliNodeCIDR).(ip.V6CIDR),
				}
			} else {
				ipv6, caliNodeCIDR := cresources.FindNodeAddress(node, apiv3.InternalIP)

				if ipv6 == nil {
					ipv6, caliNodeCIDR = cresources.FindNodeAddress(node, apiv3.ExternalIP)
				}

				if ipv6 != nil && caliNodeCIDR != nil {
					isIPv6 = true
					logrus.WithField("node ipv6 address", ipv6).Info("newNodeInfo ")
					logrus.WithField("node ipv6 cidr", caliNodeCIDR).Info("newNodeInfo ")
					nodeInfo = &l3rrNodeInfo{
						IPv6Addr: ip.FromCalicoIP(*ipv6).(ip.V6Addr),
						IPv6CIDR: ip.CIDRFromCalicoNet(*caliNodeCIDR).(ip.V6CIDR),
					}
				}
			}

			if node.Spec.BGP != nil && node.Spec.BGP.IPv4Address != "" {
				isIPv4 = true
				bgp := node.Spec.BGP
				// Use cnet.ParseCIDROrIP so we get the IP and the CIDR.  The parse functions in the ip package
				// throw away one or the other.
				ipv4, caliNodeCIDR, err := cnet.ParseCIDROrIP(bgp.IPv4Address)
				if err != nil {
					logrus.WithError(err).Panic("Failed to parse already-validated IP address")
				}
				logrus.WithField("node bgp ipv4 address", ipv4).Info("newNodeInfo ")
				logrus.WithField("node bgp ipv4 cidp", caliNodeCIDR).Info("newNodeInfo ")
				nodeInfo = &l3rrNodeInfo{
					IPv4Addr: ip.FromCalicoIP(*ipv4).(ip.V4Addr),
					IPv4CIDR: ip.CIDRFromCalicoNet(*caliNodeCIDR).(ip.V4CIDR),
				}
			} else {
				ipv4, caliNodeCIDR := cresources.FindNodeIPv4Address(node, apiv3.InternalIP)
				if ipv4 == nil {
					ipv4, caliNodeCIDR = cresources.FindNodeIPv4Address(node, apiv3.ExternalIP)
				}

				if ipv4 != nil && caliNodeCIDR != nil {
					logrus.WithField("node  ipv4 address", ipv4).Info("newNodeInfo ")
					logrus.WithField("node  ipv4 cidr", caliNodeCIDR).Info("newNodeInfo ")
					isIPv4 = true
					nodeInfo = &l3rrNodeInfo{
						IPv4Addr: ip.FromCalicoIP(*ipv4).(ip.V4Addr),
						IPv4CIDR: ip.CIDRFromCalicoNet(*caliNodeCIDR).(ip.V4CIDR),
					}
				}
			}


		if nodeInfo != nil {
			if node.Spec.Wireguard != nil && node.Spec.Wireguard.InterfaceIPv4Address != "" {
				nodeInfo.WireguardAddr = ip.FromString(node.Spec.Wireguard.InterfaceIPv4Address)
			}

			if node.Spec.BGP != nil && node.Spec.BGP.IPv4IPIPTunnelAddr != "" {
				nodeInfo.IPIPAddr = ip.FromString(node.Spec.BGP.IPv4IPIPTunnelAddr)
			}

			if node.Spec.IPv4VXLANTunnelAddr != "" {
				nodeInfo.VXLANIPv4Addr = ip.FromString(node.Spec.IPv4VXLANTunnelAddr)
				logrus.WithField("IPv4VXLANTunnelAddr ", nodeInfo.VXLANIPv4Addr).Info("newNodeInfo :")
			}

			if node.Spec.IPv6VXLANTunnelAddr != "" {
				nodeInfo.VXLANAddr = ip.FromString(node.Spec.IPv6VXLANTunnelAddr)
				logrus.WithField("IPv6VXLANTunnelAddr ", nodeInfo.VXLANAddr).Info("newNodeInfo :")
			}

			for _, a := range node.Spec.Addresses {
				parsed, _, err := cnet.ParseCIDROrIP(a.Address)
				if err == nil && parsed != nil {
					nodeInfo.Addresses = append(nodeInfo.Addresses, ip.FromCalicoIP(*parsed))
				} else {
					logrus.WithError(err).WithField("addr", a.Address).Warn("not an IP")
				}
			}
		}
	}
	logrus.WithField("IPv4Addr ", nodeInfo.IPv4Addr.String()).Info("newNodeInfo final:")
	logrus.WithField("IPv4CIDR ", nodeInfo.IPv4CIDR.String()).Info("newNodeInfo final:")
	logrus.WithField("IPv6Addr ", nodeInfo.IPv6Addr.String()).Info("newNodeInfo final:")
	logrus.WithField("IPv6CIDR ", nodeInfo.IPv6CIDR.String()).Info("newNodeInfo final:")


	c.onNodeUpdate(nodeName, nodeInfo)

	return
}

// OnHostIPUpdate gets called whenever a node IP address changes.
func (c *L3RouteResolver) OnHostIPUpdate(update api.Update) (_ bool) {
	var isIPv4, isIPv6 bool
	// Queue up a flush.
	defer func() {
		if isIPv4 {
			c.flushV4()
		}
		if isIPv6{
			c.flush()
		}
	}()

	nodeName := update.Key.(model.HostIPKey).Hostname
	logrus.WithField("node", nodeName).Debug("OnHostIPUpdate triggered")

	var newNodeInfo *l3rrNodeInfo
	if update.Value != nil {
		newCaliIP := update.Value.(*cnet.IP)
		v6Addr, ok := ip.FromCalicoIP(*newCaliIP).(ip.V6Addr)
		if ok { // Defensive; we only expect an IPv4.
			isIPv6 = true
			newNodeInfo = &l3rrNodeInfo{
				IPv6Addr: v6Addr,
				IPv6CIDR: v6Addr.AsCIDR().(ip.V6CIDR), // Don't know the CIDR so use the /32.
			}
		}
		v4Addr, ok := ip.FromCalicoIP(*newCaliIP).(ip.V4Addr)
		if ok { // Defensive; we only expect an IPv4.
			isIPv4 = true
			newNodeInfo = &l3rrNodeInfo{
				IPv4Addr: v4Addr,
				IPv4CIDR: v4Addr.AsCIDR().(ip.V4CIDR), // Don't know the CIDR so use the /32.
			}
		}
	}
	c.onNodeUpdate(nodeName, newNodeInfo)

	return
}

// onNodeUpdate updates our cache of node information as well add adding/removing the node's CIDR from the trie.
// Passing newCIDR==nil cleans up the entry in the trie.
func (c *L3RouteResolver) onNodeUpdate(nodeName string, newNodeInfo *l3rrNodeInfo) {
	oldNodeInfo, nodeExisted := c.nodeNameToNodeInfo[nodeName]
	var myNewIPv4CIDRKnown, myNewIPv6CIDRKnown bool

	if (newNodeInfo == nil && !nodeExisted) || (newNodeInfo != nil && nodeExisted && oldNodeInfo.Equal(*newNodeInfo)) {
		// No change.
		return
	}

	if nodeName == c.myNodeName {
		// Check if our CIDR has changed and if so recalculate the "same subnet" tracking.

		var myNewIPv6CIDR ip.V6CIDR

		var myNewIPv4CIDR ip.V4CIDR

		if newNodeInfo != nil {
			if newNodeInfo.IPv6CIDR.String() != "" {
				logrus.WithField("String", newNodeInfo.IPv6CIDR.String()).Info("newNodeInfo.IPv6CIDR")
				myNewIPv6CIDR = newNodeInfo.IPv6CIDR
				myNewIPv6CIDRKnown = true
				logrus.WithField("String",  oldNodeInfo.IPv6CIDR.String()).Info("oldNodeInfo.IPv6CIDR")

				if oldNodeInfo.IPv6CIDR != myNewIPv6CIDR {
					logrus.Info("visitAllRoutes execute start")
					// This node's CIDR has changed; some routes may now have an incorrect value for same-subnet.
					c.visitAllRoutes(func(r nodenameIPv6Route) {
						if r.nodeName == c.myNodeName {
							return // Ignore self.
						}
						otherNodeInfo, known := c.nodeNameToNodeInfo[r.nodeName]
						if !known {
							return // Don't know other node's CIDR so ignore for now.
						}
						otherNodesIPv6 := otherNodeInfo.IPv6Addr
						wasSameSubnet := nodeExisted && oldNodeInfo.IPv6CIDR.Contains(otherNodesIPv6)
						nowSameSubnet := myNewIPv6CIDRKnown && myNewIPv6CIDR.Contains(otherNodesIPv6)
						if wasSameSubnet != nowSameSubnet {
							logrus.WithField("route", r).Debug("Update to our subnet invalidated route")
							c.trie.MarkCIDRDirty(r.dst)
						}
					})
					logrus.Info("visitAllRoutes execute success")
				}
			}

			if newNodeInfo.IPv4CIDR.String() != "" {
				logrus.WithField("String", newNodeInfo.IPv4CIDR.String()).Info("newNodeInfo.IPv4CIDR")
				myNewIPv4CIDR = newNodeInfo.IPv4CIDR
				myNewIPv4CIDRKnown = true
				logrus.WithField("String",  oldNodeInfo.IPv4CIDR.String()).Info("oldNodeInfo.IPv4CIDR")

				if oldNodeInfo.IPv4CIDR != myNewIPv4CIDR {
					logrus.Info("visitAllIPv4Routes execute start")
					// This node's CIDR has changed; some routes may now have an incorrect value for same-subnet.
					c.visitAllIPv4Routes(func(r nodenameIPv4Route) {
						if r.nodeName == c.myNodeName {
							return // Ignore self.
						}
						otherNodeInfo, known := c.nodeNameToNodeInfo[r.nodeName]
						if !known {
							return // Don't know other node's CIDR so ignore for now.
						}
						otherNodesIPv4 := otherNodeInfo.IPv4Addr
						wasSameSubnet := nodeExisted && oldNodeInfo.IPv4CIDR.Contains(otherNodesIPv4)
						nowSameSubnet := myNewIPv4CIDRKnown && myNewIPv4CIDR.Contains(otherNodesIPv4)
						if wasSameSubnet != nowSameSubnet {
							logrus.WithField("route", r).Debug("Update to our subnet invalidated route")
							c.trieV4.MarkCIDRDirty(r.dst)
						}
					})
					logrus.Info("visitAllIPv4Routes execute success")
				}
			}

		}

	}

	// Process the tunnel addresses. These are reference counted, so handle adds followed by deletes to minimize churn.
	if newNodeInfo != nil {
		if newNodeInfo.IPIPAddr != nil {
			c.trie.AddRef(newNodeInfo.IPIPAddr.AsCIDR().(ip.V6CIDR), nodeName, RefTypeIPIP)
		}
		if newNodeInfo.VXLANAddr != nil {
			c.trie.AddRef(newNodeInfo.VXLANAddr.AsCIDR().(ip.V6CIDR), nodeName, RefTypeVXLAN)
		}
		if newNodeInfo.VXLANIPv4Addr != nil {
			c.trieV4.AddRef(newNodeInfo.VXLANIPv4Addr.AsCIDR().(ip.V4CIDR), nodeName, RefTypeVXLAN)
		}
		if newNodeInfo.WireguardAddr != nil {
			c.trie.AddRef(newNodeInfo.WireguardAddr.AsCIDR().(ip.V6CIDR), nodeName, RefTypeWireguard)
		}
	}
	if nodeExisted {
		if oldNodeInfo.IPIPAddr != nil {
			c.trie.RemoveRef(oldNodeInfo.IPIPAddr.AsCIDR().(ip.V6CIDR), nodeName, RefTypeIPIP)
		}
		if oldNodeInfo.VXLANAddr != nil {
			c.trie.RemoveRef(oldNodeInfo.VXLANAddr.AsCIDR().(ip.V6CIDR), nodeName, RefTypeVXLAN)
		}
		if oldNodeInfo.VXLANIPv4Addr != nil {
			c.trieV4.RemoveRef(oldNodeInfo.VXLANIPv4Addr.AsCIDR().(ip.V4CIDR), nodeName, RefTypeVXLAN)
		}
		if oldNodeInfo.WireguardAddr != nil {
			c.trie.RemoveRef(oldNodeInfo.WireguardAddr.AsCIDR().(ip.V6CIDR), nodeName, RefTypeWireguard)
		}
	}

	// Process the node CIDR and cache the node info.
	if nodeExisted {
		delete(c.nodeNameToNodeInfo, nodeName)
		for _, a := range oldNodeInfo.AddresesV6AsCIDRs() {
			c.trie.RemoveHost(a, nodeName)
		}
		for _, a := range oldNodeInfo.AddresesV4AsCIDRs() {
			c.trieV4.RemoveHost(a, nodeName)
		}
	}
	if newNodeInfo != nil {
		c.nodeNameToNodeInfo[nodeName] = *newNodeInfo
		for _, a := range newNodeInfo.AddresesV6AsCIDRs() {
			c.trie.AddHost(a, nodeName)
		}
		for _, a := range newNodeInfo.AddresesV4AsCIDRs() {
			c.trieV4.AddHost(a, nodeName)
		}
	}
	if myNewIPv4CIDRKnown {
		c.markAllNodeIPv4RoutesDirty(nodeName)
	}
	if myNewIPv6CIDRKnown {
		c.markAllNodeRoutesDirty(nodeName)
	}


}

func (c *L3RouteResolver) markAllNodeRoutesDirty(nodeName string) {
	c.nodeRoutes.visitRoutesForNode(nodeName, func(route nodenameIPv6Route) {
		c.trie.MarkCIDRDirty(route.dst)
	})
}

func (c *L3RouteResolver) markAllNodeIPv4RoutesDirty(nodeName string) {
	c.nodeIPv4Routes.visitRoutesForNode(nodeName, func(route nodenameIPv4Route) {
		c.trieV4.MarkCIDRDirty(route.dst)
	})
}

func (c *L3RouteResolver) visitAllRoutes(v func(route nodenameIPv6Route)) {
	c.trie.t.Visit(func(cidr ip.V6CIDR, data interface{}) bool {
		// Construct a nodenameRoute to pass to the visiting function.
		ri := c.trie.t.Get(cidr).(RouteInfo)
		nnr := nodenameIPv6Route{dst: cidr}
		if len(ri.Refs) > 0 {
			// From a Ref.
			nnr.nodeName = ri.Refs[0].NodeName
		} else if ri.Block.NodeName != "" {
			// From IPAM.
			nnr.nodeName = ri.Block.NodeName
		} else {
			// No host associated with route.
			return true
		}

		v(nnr)
		return true
	})
}

func (c *L3RouteResolver) visitAllIPv4Routes(v func(route nodenameIPv4Route)) {
	c.trieV4.t.Visit(func(cidr ip.V4CIDR, data interface{}) bool {
		// Construct a nodenameRoute to pass to the visiting function.
		ri := c.trieV4.t.Get(cidr).(RouteInfo)
		nnr := nodenameIPv4Route{dst: cidr}
		if len(ri.Refs) > 0 {
			// From a Ref.
			nnr.nodeName = ri.Refs[0].NodeName
		} else if ri.Block.NodeName != "" {
			// From IPAM.
			nnr.nodeName = ri.Block.NodeName
		} else {
			// No host associated with route.
			return true
		}

		v(nnr)
		return true
	})
}

// OnPoolUpdate gets called whenever an IP pool changes.
func (c *L3RouteResolver) OnPoolUpdate(update api.Update) (_ bool) {
	// Queue up a flush.
	var isIPv4, isIPv6 bool

	defer func() {
		if isIPv4 {
			c.flushV4()
		}
		if isIPv6 {
			c.flush()
		}
	}()

	k := update.Key.(model.IPPoolKey)
	poolKey := k.String()
	oldPool, oldPoolExists := c.allPools[poolKey]

	oldPoolType := proto.IPPoolType_NONE
	if oldPoolExists {
		// Need explicit oldPoolExists check so that we don't pass a zero-struct to poolTypeForPool.
		oldPoolType = c.poolTypeForPool(&oldPool)
	}
	var newPool *model.IPPool
	if update.Value != nil {
		newPool = update.Value.(*model.IPPool)
		if len(newPool.CIDR.IP.To16()) == 0 {
			isIPv4 = true
		}else {
			isIPv6 = true
		}

	}
	newPoolType := c.poolTypeForPool(newPool)
	logCxt := logrus.WithFields(logrus.Fields{"oldType": oldPoolType, "newType": newPoolType})
	if newPool != nil && newPoolType != proto.IPPoolType_NONE {
		logCxt.Info("Pool is active")
		c.allPools[poolKey] = *newPool
		if newPool.CIDR.Version() == 4 {
			poolCIDRV4 := ip.CIDRFromCalicoNet(newPool.CIDR).(ip.V4CIDR)
			crossSubnet := newPool.IPIPMode == encap.CrossSubnet || newPool.VXLANMode == encap.CrossSubnet
			c.trieV4.UpdatePool(poolCIDRV4, newPoolType, newPool.Masquerade, crossSubnet)
		} else {
			poolCIDRV6 := ip.CIDRFromCalicoNet(newPool.CIDR).(ip.V6CIDR)
			crossSubnet := newPool.IPIPMode == encap.CrossSubnet || newPool.VXLANMode == encap.CrossSubnet
			c.trie.UpdatePool(poolCIDRV6, newPoolType, newPool.Masquerade, crossSubnet)
		}

	} else {
		delete(c.allPools, poolKey)
		if oldPool.CIDR.Version() == 4 {
			poolCIDR := ip.CIDRFromCalicoNet(oldPool.CIDR).(ip.V4CIDR)
			c.trieV4.RemovePool(poolCIDR)
		} else {
			poolCIDR := ip.CIDRFromCalicoNet(oldPool.CIDR).(ip.V6CIDR)
			c.trie.RemovePool(poolCIDR)
		}

	}

	return
}

func (c *L3RouteResolver) poolTypeForPool(pool *model.IPPool) proto.IPPoolType {
	if pool == nil {
		return proto.IPPoolType_NONE
	}
	if pool.VXLANMode != encap.Undefined {
		return proto.IPPoolType_VXLAN
	}
	if pool.IPIPMode != encap.Undefined {
		return proto.IPPoolType_IPIP
	}
	return proto.IPPoolType_NO_ENCAP
}

// v4RoutesFromBlock returns a list of routes which should exist based on the provided
// allocation block.
func (c *L3RouteResolver) v6RoutesFromBlock(b *model.AllocationBlock) map[string]nodenameIPv6Route {
	if len(b.CIDR.IP.To16()) == 0 {
		logrus.Debug("Ignoring IPv4 block")
		return nil
	}

	routes := make(map[string]nodenameIPv6Route)
	for _, alloc := range b.NonAffineAllocations() {
		if alloc.Host == "" {
			logrus.WithField("IP", alloc.Addr).Warn(
				"Unable to create route for IP; the node it belongs to was not recorded in IPAM")
			continue
		}
		r := nodenameIPv6Route{
			dst:      ip.CIDRFromNetIP(alloc.Addr.IP).(ip.V6CIDR),
			nodeName: alloc.Host,
		}
		routes[r.Key()] = r
	}

	host := b.Host()
	if host != "" {
		logrus.WithField("host", host).Debug("Block has a host, including block-via-host route")
		r := nodenameIPv6Route{
			dst:      ip.CIDRFromCalicoNet(b.CIDR).(ip.V6CIDR),
			nodeName: host,
		}
		routes[r.Key()] = r
	}

	return routes
}

func (c *L3RouteResolver) v4RoutesFromBlock(b *model.AllocationBlock) map[string]nodenameIPv4Route {
	if len(b.CIDR.IP.To16()) != 0 {
		logrus.Debug("Ignoring IPv6 block")
		return nil
	}

	routes := make(map[string]nodenameIPv4Route)
	for _, alloc := range b.NonAffineAllocations() {
		if alloc.Host == "" {
			logrus.WithField("IP", alloc.Addr).Warn(
				"Unable to create route for IP; the node it belongs to was not recorded in IPAM")
			continue
		}
		r := nodenameIPv4Route{
			dst:      ip.CIDRFromNetIP(alloc.Addr.IP).(ip.V4CIDR),
			nodeName: alloc.Host,
		}
		routes[r.Key()] = r
	}

	host := b.Host()
	if host != "" {
		logrus.WithField("host", host).Debug("Block has a host, including block-via-host route")
		r := nodenameIPv4Route{
			dst:      ip.CIDRFromCalicoNet(b.CIDR).(ip.V4CIDR),
			nodeName: host,
		}
		routes[r.Key()] = r
	}

	return routes
}

// flush() iterates over the CIDRs that are marked dirty in the trie and sends any route updates
// that it finds.
func (c *L3RouteResolver) flush() {
	var buf []ip.V6TrieEntry
	c.trie.dirtyCIDRs.Iter(func(item interface{}) error {
		logCxt := logrus.WithField("cidr", item)
		logCxt.Debug("Flushing dirty route")
		cidr := item.(ip.V6CIDR)

		// We know the CIDR may be dirty, look up the path through the trie to the CIDR.  This will
		// give us the information about the enclosing CIDRs.  For example, if we have:
		// - IP pool     10.0.0.0/16 VXLAN
		// - IPAM block  10.0.1.0/26 node x
		// - IP          10.0.0.1/32 node y
		// Then, we'll see the pool, block and IP in turn on the lookup path allowing us to collect the
		// relevant information from each.
		buf = c.trie.t.LookupPath(buf, cidr)

		if len(buf) == 0 {
			// CIDR is not in the trie.  Nothing to do.  Route removed before it had even been sent?
			logCxt.Debug("CIDR not in trie, ignoring.")
			return set.RemoveItem
		}

		// Otherwise, check if the route is removed.
		ri := buf[len(buf)-1].Data.(RouteInfo)
		if ri.WasSent && !ri.IsValidRoute() {
			logCxt.Debug("CIDR was sent before but now needs to be removed.")
			c.callbacks.OnRouteRemove(cidr.String())
			c.trie.SetRouteSent(cidr, false)
			return set.RemoveItem
		}

		rt := &proto.RouteUpdate{
			Type:       proto.RouteType_CIDR_INFO,
			IpPoolType: proto.IPPoolType_NONE,
			Dst:        cidr.String(),
		}
		poolAllowsCrossSubnet := false
		for _, entry := range buf {
			ri := entry.Data.(RouteInfo)
			if ri.Pool.Type != proto.IPPoolType_NONE {
				logCxt.WithField("type", ri.Pool.Type).Debug("Found containing IP pool.")
				rt.IpPoolType = ri.Pool.Type
			}
			if ri.Pool.NATOutgoing {
				logCxt.Debug("NAT outgoing enabled on this CIDR.")
				rt.NatOutgoing = true
			}
			if ri.Pool.CrossSubnet {
				logCxt.Debug("Cross-subnet enabled on this CIDR.")
				poolAllowsCrossSubnet = true
			}
			if ri.Block.NodeName != "" {
				rt.DstNodeName = ri.Block.NodeName
				if rt.DstNodeName == c.myNodeName {
					logCxt.Debug("Local workload route.")
					rt.Type = proto.RouteType_LOCAL_WORKLOAD
				} else {
					logCxt.Debug("Remote workload route.")
					rt.Type = proto.RouteType_REMOTE_WORKLOAD
				}
			}
			if len(ri.Host.NodeNames) > 0 {
				rt.DstNodeName = ri.Host.NodeNames[0]

				if rt.DstNodeName == c.myNodeName {
					logCxt.Debug("Local host route.")
					rt.Type = proto.RouteType_LOCAL_HOST
				} else {
					logCxt.Debug("Remote host route.")
					rt.Type = proto.RouteType_REMOTE_HOST
				}
			}

			if len(ri.Refs) > 0 {
				// At least one Ref exists with this IP. It may be on this node, or a remote node.
				// In steady state we only ever expect a single workload Ref for this CIDR, or multiple tunnel Refs
				// sharing the same CIDR. However, there are rare transient cases we must handle where we may have
				// multiple workload, or workload and tunnel, or multiple node Refs with the same IP. Since this will be
				// transient, we can always just use the first entry (and related tunnel entries)
				rt.DstNodeName = ri.Refs[0].NodeName
				if ri.Refs[0].RefType == RefTypeWEP {
					// This is not a tunnel ref, so must be a workload.
					if ri.Refs[0].NodeName == c.myNodeName {
						rt.Type = proto.RouteType_LOCAL_WORKLOAD
						rt.LocalWorkload = true
					} else {
						rt.Type = proto.RouteType_REMOTE_WORKLOAD
					}
				} else {
					// This is a tunnel ref, set type and also store the tunnel type in the route. It is possible for
					// multiple tunnels to have the same IP, so collate all tunnel types on the same node.
					if ri.Refs[0].NodeName == c.myNodeName {
						rt.Type = proto.RouteType_LOCAL_TUNNEL
					} else {
						rt.Type = proto.RouteType_REMOTE_TUNNEL
					}

					rt.TunnelType = &proto.TunnelType{}
					for _, ref := range ri.Refs {
						if ref.NodeName != ri.Refs[0].NodeName {
							// This reference is on a different node to entry 0, so don't include.
							continue
						}

						switch ref.RefType {
						case RefTypeIPIP:
							rt.TunnelType.Ipip = true
						case RefTypeVXLAN:
							rt.TunnelType.Vxlan = true
						case RefTypeWireguard:
							rt.TunnelType.Wireguard = true
						}
					}
				}
			}
		}

		if rt.DstNodeName != "" {
			dstNodeInfo, exists := c.nodeNameToNodeInfo[rt.DstNodeName]
			if exists {
				rt.DstNodeIp = dstNodeInfo.IPv6Addr.String()
			}
		}
		rt.SameSubnet = poolAllowsCrossSubnet && c.nodeInOurSubnet(rt.DstNodeName)

		logrus.WithField("route", rt).Debug("Sending route")
		c.callbacks.OnRouteUpdate(rt)
		c.trie.SetRouteSent(cidr, true)

		return set.RemoveItem
	})
}

func (c *L3RouteResolver) flushV4() {
	var buf []ip.V4TrieEntry
	c.trieV4.dirtyCIDRs.Iter(func(item interface{}) error {
		logCxt := logrus.WithField("cidr", item)
		logCxt.Debug("Flushing dirty route")
		cidr := item.(ip.V4CIDR)

		// We know the CIDR may be dirty, look up the path through the trie to the CIDR.  This will
		// give us the information about the enclosing CIDRs.  For example, if we have:
		// - IP pool     10.0.0.0/16 VXLAN
		// - IPAM block  10.0.1.0/26 node x
		// - IP          10.0.0.1/32 node y
		// Then, we'll see the pool, block and IP in turn on the lookup path allowing us to collect the
		// relevant information from each.
		buf = c.trieV4.t.LookupPath(buf, cidr)

		if len(buf) == 0 {
			// CIDR is not in the trie.  Nothing to do.  Route removed before it had even been sent?
			logCxt.Debug("CIDR not in trie, ignoring.")
			return set.RemoveItem
		}

		// Otherwise, check if the route is removed.
		ri := buf[len(buf)-1].Data.(RouteInfo)
		if ri.WasSent && !ri.IsValidRoute() {
			logCxt.Debug("CIDR was sent before but now needs to be removed.")
			c.callbacks.OnRouteRemove(cidr.String())
			c.trieV4.SetRouteSent(cidr, false)
			return set.RemoveItem
		}

		rt := &proto.RouteUpdate{
			Type:       proto.RouteType_CIDR_INFO,
			IpPoolType: proto.IPPoolType_NONE,
			Dst:        cidr.String(),
		}
		poolAllowsCrossSubnet := false
		for _, entry := range buf {
			ri := entry.Data.(RouteInfo)
			if ri.Pool.Type != proto.IPPoolType_NONE {
				logCxt.WithField("type", ri.Pool.Type).Debug("Found containing IP pool.")
				rt.IpPoolType = ri.Pool.Type
			}
			if ri.Pool.NATOutgoing {
				logCxt.Debug("NAT outgoing enabled on this CIDR.")
				rt.NatOutgoing = true
			}
			if ri.Pool.CrossSubnet {
				logCxt.Debug("Cross-subnet enabled on this CIDR.")
				poolAllowsCrossSubnet = true
			}
			if ri.Block.NodeName != "" {
				rt.DstNodeName = ri.Block.NodeName
				if rt.DstNodeName == c.myNodeName {
					logCxt.Debug("Local workload route.")
					rt.Type = proto.RouteType_LOCAL_WORKLOAD
				} else {
					logCxt.Debug("Remote workload route.")
					rt.Type = proto.RouteType_REMOTE_WORKLOAD
				}
			}
			if len(ri.Host.NodeNames) > 0 {
				rt.DstNodeName = ri.Host.NodeNames[0]

				if rt.DstNodeName == c.myNodeName {
					logCxt.Debug("Local host route.")
					rt.Type = proto.RouteType_LOCAL_HOST
				} else {
					logCxt.Debug("Remote host route.")
					rt.Type = proto.RouteType_REMOTE_HOST
				}
			}

			if len(ri.Refs) > 0 {
				// At least one Ref exists with this IP. It may be on this node, or a remote node.
				// In steady state we only ever expect a single workload Ref for this CIDR, or multiple tunnel Refs
				// sharing the same CIDR. However, there are rare transient cases we must handle where we may have
				// multiple workload, or workload and tunnel, or multiple node Refs with the same IP. Since this will be
				// transient, we can always just use the first entry (and related tunnel entries)
				rt.DstNodeName = ri.Refs[0].NodeName
				if ri.Refs[0].RefType == RefTypeWEP {
					// This is not a tunnel ref, so must be a workload.
					if ri.Refs[0].NodeName == c.myNodeName {
						rt.Type = proto.RouteType_LOCAL_WORKLOAD
						rt.LocalWorkload = true
					} else {
						rt.Type = proto.RouteType_REMOTE_WORKLOAD
					}
				} else {
					// This is a tunnel ref, set type and also store the tunnel type in the route. It is possible for
					// multiple tunnels to have the same IP, so collate all tunnel types on the same node.
					if ri.Refs[0].NodeName == c.myNodeName {
						rt.Type = proto.RouteType_LOCAL_TUNNEL
					} else {
						rt.Type = proto.RouteType_REMOTE_TUNNEL
					}

					rt.TunnelType = &proto.TunnelType{}
					for _, ref := range ri.Refs {
						if ref.NodeName != ri.Refs[0].NodeName {
							// This reference is on a different node to entry 0, so don't include.
							continue
						}

						switch ref.RefType {
						case RefTypeIPIP:
							rt.TunnelType.Ipip = true
						case RefTypeVXLAN:
							rt.TunnelType.Vxlan = true
						case RefTypeWireguard:
							rt.TunnelType.Wireguard = true
						}
					}
				}
			}
		}

		if rt.DstNodeName != "" {
			dstNodeInfo, exists := c.nodeNameToNodeInfo[rt.DstNodeName]
			if exists {
				rt.DstNodeIp = dstNodeInfo.IPv4Addr.String()
			}
		}
		rt.SameSubnet = poolAllowsCrossSubnet && c.nodeInOurSubnet(rt.DstNodeName)

		logrus.WithField("route", rt).Debug("Sending route")
		c.callbacks.OnRouteUpdate(rt)
		c.trieV4.SetRouteSent(cidr, true)

		return set.RemoveItem
	})
}

// nodeInOurSubnet returns true if the IP of the given node is known and it's in our subnet.
// Return false if either the remote IP or our subnet is not known.
func (c *L3RouteResolver) nodeInOurSubnet(name string) bool {
	localNodeInfo, exists := c.nodeNameToNodeInfo[c.myNodeName]
	if !exists {
		return false
	}

	nodeInfo, exists := c.nodeNameToNodeInfo[name]
	if !exists {
		return false
	}

	return localNodeInfo.IPv6CIDR.Contains(nodeInfo.IPv6Addr)
}

func (c *L3RouteResolver) nodeIPv4InOurSubnet(name string) bool {
	localNodeInfo, exists := c.nodeNameToNodeInfo[c.myNodeName]
	if !exists {
		return false
	}

	nodeInfo, exists := c.nodeNameToNodeInfo[name]
	if !exists {
		return false
	}

	return localNodeInfo.IPv4CIDR.Contains(nodeInfo.IPv4Addr)
}

// nodenameRoute is the L3RouteResolver's internal representation of a route.
type nodenameIPv6Route struct {
	nodeName string
	dst      ip.V6CIDR
}

func (r nodenameIPv6Route) Key() string {
	return r.dst.String()
}

func (r nodenameIPv6Route) String() string {
	return fmt.Sprintf("hostnameIPv6Route(dst: %s, node: %s)", r.dst.String(), r.nodeName)
}

type nodenameIPv4Route struct {
	nodeName string
	dst      ip.V4CIDR
}

func (r nodenameIPv4Route) Key() string {
	return r.dst.String()
}

func (r nodenameIPv4Route) String() string {
	return fmt.Sprintf("hostnameIPv4Route(dst: %s, node: %s)", r.dst.String(), r.nodeName)
}

// RouteTrie stores the information that we've gleaned from various resources in a way that allows us to
//
// - Look up a CIDR and find all the information that we know about the containing CIDRs.
//   Example: if we look up a workload /32 CIDR then we'll also find the IP pool that contains it.
// - Deal with collisions where resources from different sources share the same CIDR.
//   Example: an IP pool and an IPAM block can share the same CIDR.  When we do a lookup, we want to know
//   about both the pool and the block.
//
// More examples of nesting and collisions to be aware of:
//
// - Disabled IPAM pools that contain no blocks, which are used for tagging "external" IPs as safe destinations that
//   don't require SNAT and for adding IP ranges for BIRD to export.
// - IPAM blocks that are /32s so they overlap with the pod IP inside them (and potentially with a
//   misconfigured host IP).
// - Transient misconfigurations during a resync where we may see things out of order (for example, two hosts
//   sharing an IP).
// - In future, /32s that we've learned from workload endpoints that are not contained within IP pools.
//
// Approach: for each CIDR in the trie, we store a RouteInfo struct, which has a disjoint nested struct for
// tracking data from each source.  All updates are done via the updateCIDR method, which handles cleaning up
// RouteInfo structs that are empty.
//
// The RouteTrie maintains a set of dirty CIDRs.  When an IPAM pool is updated, all the CIDRs under it are
// marked dirty.
type IPv6RouteTrie struct {
	t          *ip.V6Trie
	dirtyCIDRs set.Set
}

func NewIPv6RouteTrie() *IPv6RouteTrie {
	return &IPv6RouteTrie{
		t:          &ip.V6Trie{},
		dirtyCIDRs: set.New(),
	}
}

type IPv4RouteTrie struct {
	t          *ip.V4Trie
	dirtyCIDRs set.Set
}

func NewIPv4RouteTrie() *IPv4RouteTrie {
	return &IPv4RouteTrie{
		t:          &ip.V4Trie{},
		dirtyCIDRs: set.New(),
	}
}

func (r *IPv6RouteTrie) UpdatePool(cidr ip.V6CIDR, poolType proto.IPPoolType, natOutgoing bool, crossSubnet bool) {
	logrus.WithFields(logrus.Fields{
		"cidr":        cidr,
		"poolType":    poolType,
		"nat":         natOutgoing,
		"crossSubnet": crossSubnet,
	}).Debug("IP pool update")
	changed := r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Pool.Type = poolType
		ri.Pool.NATOutgoing = natOutgoing
		ri.Pool.CrossSubnet = crossSubnet
	})
	if !changed {
		return
	}
	r.markChildrenDirty(cidr)
}

func (r *IPv4RouteTrie) UpdatePool(cidr ip.V4CIDR, poolType proto.IPPoolType, natOutgoing bool, crossSubnet bool) {
	logrus.WithFields(logrus.Fields{
		"cidr":        cidr,
		"poolType":    poolType,
		"nat":         natOutgoing,
		"crossSubnet": crossSubnet,
	}).Debug("IP pool update")
	changed := r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Pool.Type = poolType
		ri.Pool.NATOutgoing = natOutgoing
		ri.Pool.CrossSubnet = crossSubnet
	})
	if !changed {
		return
	}
	r.markChildrenDirty(cidr)
}

func (r *IPv6RouteTrie) markChildrenDirty(cidr ip.V6CIDR) {
	// TODO: avoid full scan to mark children dirty
	r.t.Visit(func(c ip.V6CIDR, data interface{}) bool {
		if cidr.Contains(c.Addr().(ip.V6Addr)) {
			r.MarkCIDRDirty(c)
		}
		return true
	})
}

func (r *IPv4RouteTrie) markChildrenDirty(cidr ip.V4CIDR) {
	// TODO: avoid full scan to mark children dirty
	r.t.Visit(func(c ip.V4CIDR, data interface{}) bool {
		if cidr.Contains(c.Addr().(ip.V4Addr)) {
			r.MarkCIDRDirty(c)
		}
		return true
	})
}

func (r *IPv6RouteTrie) MarkCIDRDirty(cidr ip.CIDR) {
	r.dirtyCIDRs.Add(cidr)
}

func (r *IPv6RouteTrie) RemovePool(cidr ip.V6CIDR) {
	r.UpdatePool(cidr, proto.IPPoolType_NONE, false, false)
}

func (r *IPv4RouteTrie) MarkCIDRDirty(cidr ip.CIDR) {
	r.dirtyCIDRs.Add(cidr)
}

func (r *IPv4RouteTrie) RemovePool(cidr ip.V4CIDR) {
	r.UpdatePool(cidr, proto.IPPoolType_NONE, false, false)
}

func (r *IPv6RouteTrie) UpdateBlockRoute(cidr ip.V6CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Block.NodeName = nodeName
	})
}

func (r *IPv6RouteTrie) RemoveBlockRoute(cidr ip.V6CIDR) {
	r.UpdateBlockRoute(cidr, "")
}

func (r *IPv4RouteTrie) UpdateBlockRoute(cidr ip.V4CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Block.NodeName = nodeName
	})
}

func (r *IPv4RouteTrie) RemoveBlockRoute(cidr ip.V4CIDR) {
	r.UpdateBlockRoute(cidr, "")
}

func (r *IPv6RouteTrie) AddHost(cidr ip.V6CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Host.NodeNames = append(ri.Host.NodeNames, nodeName)
		if len(ri.Host.NodeNames) > 1 {
			logrus.WithFields(logrus.Fields{
				"cidr":  cidr,
				"nodes": ri.Host.NodeNames,
			}).Warn("Some nodes share IP address, route calculation may choose wrong node.")
			// For determinism in case we have two hosts sharing an IP, sort the entries.
			sort.Strings(ri.Host.NodeNames)
		}
	})
}

func (r *IPv4RouteTrie) AddHost(cidr ip.V4CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Host.NodeNames = append(ri.Host.NodeNames, nodeName)
		if len(ri.Host.NodeNames) > 1 {
			logrus.WithFields(logrus.Fields{
				"cidr":  cidr,
				"nodes": ri.Host.NodeNames,
			}).Warn("Some nodes share IP address, route calculation may choose wrong node.")
			// For determinism in case we have two hosts sharing an IP, sort the entries.
			sort.Strings(ri.Host.NodeNames)
		}
	})
}

func (r *IPv6RouteTrie) RemoveHost(cidr ip.V6CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		var ns []string
		for _, n := range ri.Host.NodeNames {
			if n == nodeName {
				continue
			}
			ns = append(ns, n)
		}
		ri.Host.NodeNames = ns
	})
}

func (r *IPv4RouteTrie) RemoveHost(cidr ip.V4CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		var ns []string
		for _, n := range ri.Host.NodeNames {
			if n == nodeName {
				continue
			}
			ns = append(ns, n)
		}
		ri.Host.NodeNames = ns
	})
}

func (r *IPv6RouteTrie) AddRef(cidr ip.V6CIDR, nodename string, rt RefType) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		// Find the ref in the list for this nodename,
		// if it exists. If it doesn't, we'll add it below.
		for i := range ri.Refs {
			// Reference count
			if ri.Refs[i].NodeName == nodename && ri.Refs[i].RefType == rt {
				// Found an existing ref. Just increment the RefCount
				// and return.
				ri.Refs[i].RefCount++
				return
			}
		}

		// If it doesn't already exist, add it to the slice and
		// sort the slice based on nodename and ref type to make sure we are not dependent
		// on event ordering.
		ref := Ref{NodeName: nodename, RefCount: 1, RefType: rt}
		ri.Refs = append(ri.Refs, ref)
		sort.Slice(ri.Refs, func(i, j int) bool {
			if ri.Refs[i].NodeName == ri.Refs[j].NodeName {
				return ri.Refs[i].RefType < ri.Refs[j].RefType
			}
			return ri.Refs[i].NodeName < ri.Refs[j].NodeName
		})
	})
}

func (r *IPv4RouteTrie) AddRef(cidr ip.V4CIDR, nodename string, rt RefType) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		// Find the ref in the list for this nodename,
		// if it exists. If it doesn't, we'll add it below.
		for i := range ri.Refs {
			// Reference count
			if ri.Refs[i].NodeName == nodename && ri.Refs[i].RefType == rt {
				// Found an existing ref. Just increment the RefCount
				// and return.
				ri.Refs[i].RefCount++
				return
			}
		}

		// If it doesn't already exist, add it to the slice and
		// sort the slice based on nodename and ref type to make sure we are not dependent
		// on event ordering.
		ref := Ref{NodeName: nodename, RefCount: 1, RefType: rt}
		ri.Refs = append(ri.Refs, ref)
		sort.Slice(ri.Refs, func(i, j int) bool {
			if ri.Refs[i].NodeName == ri.Refs[j].NodeName {
				return ri.Refs[i].RefType < ri.Refs[j].RefType
			}
			return ri.Refs[i].NodeName < ri.Refs[j].NodeName
		})
	})
}

func (r *IPv6RouteTrie) RemoveRef(cidr ip.V6CIDR, nodename string, rt RefType) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		for i := range ri.Refs {
			if ri.Refs[i].NodeName == nodename && ri.Refs[i].RefType == rt {
				// Decref the Ref.
				ri.Refs[i].RefCount--
				if ri.Refs[i].RefCount < 0 {
					logrus.WithField("cidr", cidr).Panic("BUG: Asked to decref a workload past 0.")
				} else if ri.Refs[i].RefCount == 0 {
					// Remove it from the list.
					ri.Refs = append(ri.Refs[:i], ri.Refs[i+1:]...)
				}
				if len(ri.Refs) == 0 {
					ri.Refs = nil
				}
				return
			}
		}

		// Unable to find the requested Ref.
		logrus.WithField("cidr", cidr).Panic("BUG: Asked to decref a workload that doesn't exist.")
	})
}

func (r *IPv4RouteTrie) RemoveRef(cidr ip.V4CIDR, nodename string, rt RefType) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		for i := range ri.Refs {
			if ri.Refs[i].NodeName == nodename && ri.Refs[i].RefType == rt {
				// Decref the Ref.
				ri.Refs[i].RefCount--
				if ri.Refs[i].RefCount < 0 {
					logrus.WithField("cidr", cidr).Panic("BUG: Asked to decref a workload past 0.")
				} else if ri.Refs[i].RefCount == 0 {
					// Remove it from the list.
					ri.Refs = append(ri.Refs[:i], ri.Refs[i+1:]...)
				}
				if len(ri.Refs) == 0 {
					ri.Refs = nil
				}
				return
			}
		}

		// Unable to find the requested Ref.
		logrus.WithField("cidr", cidr).Panic("BUG: Asked to decref a workload that doesn't exist.")
	})
}

func (r *IPv6RouteTrie) SetRouteSent(cidr ip.V6CIDR, sent bool) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.WasSent = sent
	})
}

func (r *IPv4RouteTrie) SetRouteSent(cidr ip.V4CIDR, sent bool) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.WasSent = sent
	})
}

func (r IPv6RouteTrie) updateCIDR(cidr ip.V6CIDR, updateFn func(info *RouteInfo)) bool {
	// Get the RouteInfo for the given CIDR and take a copy so we can compare.
	ri := r.Get(cidr)
	riCopy := ri.Copy()

	// Apply the update, whatever that is.
	updateFn(&ri)

	// Check if the update was a no-op.
	if riCopy.Equals(ri) {
		// Change was a no-op, ignore.
		logrus.WithField("cidr", cidr).Debug("Ignoring no-op change")
		return false
	}

	// Not a no-op; mark CIDR as dirty.
	logrus.WithFields(logrus.Fields{"old": riCopy, "new": ri}).Debug("Route updated, marking dirty.")
	r.MarkCIDRDirty(cidr)
	if ri.IsZero() {
		// No longer have *anything* to track about this CIDR, clean it up.
		logrus.WithField("cidr", cidr).Debug("RouteInfo is zero, cleaning up.")
		r.t.Delete(cidr)
		return true
	}
	r.t.Update(cidr, ri)
	return true
}

func (r IPv4RouteTrie) updateCIDR(cidr ip.V4CIDR, updateFn func(info *RouteInfo)) bool {
	// Get the RouteInfo for the given CIDR and take a copy so we can compare.
	ri := r.Get(cidr)
	riCopy := ri.Copy()

	// Apply the update, whatever that is.
	updateFn(&ri)

	// Check if the update was a no-op.
	if riCopy.Equals(ri) {
		// Change was a no-op, ignore.
		logrus.WithField("cidr", cidr).Debug("Ignoring no-op change")
		return false
	}

	// Not a no-op; mark CIDR as dirty.
	logrus.WithFields(logrus.Fields{"old": riCopy, "new": ri}).Debug("Route updated, marking dirty.")
	r.MarkCIDRDirty(cidr)
	if ri.IsZero() {
		// No longer have *anything* to track about this CIDR, clean it up.
		logrus.WithField("cidr", cidr).Debug("RouteInfo is zero, cleaning up.")
		r.t.Delete(cidr)
		return true
	}
	r.t.Update(cidr, ri)
	return true
}

func (r IPv6RouteTrie) Get(cidr ip.V6CIDR) RouteInfo {
	ri := r.t.Get(cidr)
	if ri == nil {
		return RouteInfo{}
	}
	return ri.(RouteInfo)
}

func (r IPv4RouteTrie) Get(cidr ip.V4CIDR) RouteInfo {
	ri := r.t.Get(cidr)
	if ri == nil {
		return RouteInfo{}
	}
	return ri.(RouteInfo)
}

type RouteInfo struct {
	// Pool contains information extracted from the IP pool that has this CIDR.
	Pool struct {
		Type        proto.IPPoolType // Only set if this CIDR represents an IP pool
		NATOutgoing bool
		CrossSubnet bool
	}

	// Block contains route information extracted from IPAM blocks.
	Block struct {
		NodeName string // Set for each route that comes from an IPAM block.
	}

	// Host contains information extracted from the node/host config updates.
	Host struct {
		NodeNames []string // set if this CIDR _is_ a node's own IP.
	}

	// Refs contains information extracted from workload endpoints, or tunnel addresses extracted from the node.
	Refs []Ref

	// WasSent is set to true when the route is sent downstream.
	WasSent bool
}

type RefType byte

const (
	RefTypeWEP RefType = iota
	RefTypeWireguard
	RefTypeIPIP
	RefTypeVXLAN
)

type Ref struct {
	// Count of Refs that have this CIDR.  Normally, for WEPs this will be 0 or 1 but Felix has to be tolerant
	// to bad data (two Refs with the same CIDR) so we do ref counting. For tunnel IPs, multiple tunnels may share the
	// same IP, so again ref counting is necessary here.
	RefCount int

	// The type of reference.
	RefType RefType

	// NodeName contains the nodename for this Ref / CIDR.
	NodeName string
}

// IsValidRoute returns true if the RouteInfo contains some information about a CIDR, i.e. if this route
// should be sent downstream.  This _excludes_ the WasSent flag, which we use to track whether a route with
// this CIDR was previously sent.  If IsValidRoute() returns false but WasSent is true then we need to withdraw
// the route.
func (r RouteInfo) IsValidRoute() bool {
	return r.Pool.Type != proto.IPPoolType_NONE ||
		r.Block.NodeName != "" ||
		len(r.Host.NodeNames) > 0 ||
		r.Pool.NATOutgoing ||
		len(r.Refs) > 0
}

// Copy returns a copy of the RouteInfo. Since some fields are pointers, we need to
// explicitly copy them so that they are not shared between the copies.
func (r RouteInfo) Copy() RouteInfo {
	cp := r
	if len(r.Refs) != 0 {
		cp.Refs = make([]Ref, len(r.Refs))
		copy(cp.Refs, r.Refs)
	}
	return cp
}

// IsZero() returns true if this node in the trie now contains no tracking information at all and is
// ready for deletion.
func (r RouteInfo) IsZero() bool {
	return !r.WasSent && !r.IsValidRoute()
}

func (r RouteInfo) Equals(other RouteInfo) bool {
	return reflect.DeepEqual(r, other)
}

// nodeRoutes is used for efficiently looking up routes associated with a node.
// It uses a reference counter so that we can properly handle intermediate cases where
// the same CIDR might appear twice.
type nodeIPv6Routes struct {
	cache map[string]map[ip.V6CIDR]int
}

func newNodeRoutes() nodeIPv6Routes {
	return nodeIPv6Routes{
		cache: map[string]map[ip.V6CIDR]int{},
	}
}

func (nr *nodeIPv6Routes) Add(r nodenameIPv6Route) {
	if _, ok := nr.cache[r.nodeName]; !ok {
		nr.cache[r.nodeName] = map[ip.V6CIDR]int{r.dst: 0}
	}
	nr.cache[r.nodeName][r.dst]++
}

func (nr *nodeIPv6Routes) Remove(r nodenameIPv6Route) {
	_, ok := nr.cache[r.nodeName]
	if !ok {
		logrus.WithField("route", r).Panic("BUG: Asked to decref for node that doesn't exist")
	}
	nr.cache[r.nodeName][r.dst]--
	if nr.cache[r.nodeName][r.dst] == 0 {
		delete(nr.cache[r.nodeName], r.dst)
	} else if nr.cache[r.nodeName][r.dst] < 0 {
		logrus.WithField("route", r).Panic("BUG: Asked to decref a route past 0.")
	}
	if len(nr.cache[r.nodeName]) == 0 {
		delete(nr.cache, r.nodeName)
	}
}

func (nr *nodeIPv6Routes) visitRoutesForNode(nodename string, v func(nodenameIPv6Route)) {
	for cidr := range nr.cache[nodename] {
		v(nodenameIPv6Route{nodeName: nodename, dst: cidr})
	}
}

type nodeIPv4Routes struct {
	cache map[string]map[ip.V4CIDR]int
}

func newNodeIPv4Routes() nodeIPv4Routes {
	return nodeIPv4Routes{
		cache: map[string]map[ip.V4CIDR]int{},
	}
}

func (nr *nodeIPv4Routes) Add(r nodenameIPv4Route) {
	if _, ok := nr.cache[r.nodeName]; !ok {
		nr.cache[r.nodeName] = map[ip.V4CIDR]int{r.dst: 0}
	}
	nr.cache[r.nodeName][r.dst]++
}

func (nr *nodeIPv4Routes) Remove(r nodenameIPv4Route) {
	_, ok := nr.cache[r.nodeName]
	if !ok {
		logrus.WithField("route", r).Panic("BUG: Asked to decref for node that doesn't exist")
	}
	nr.cache[r.nodeName][r.dst]--
	if nr.cache[r.nodeName][r.dst] == 0 {
		delete(nr.cache[r.nodeName], r.dst)
	} else if nr.cache[r.nodeName][r.dst] < 0 {
		logrus.WithField("route", r).Panic("BUG: Asked to decref a route past 0.")
	}
	if len(nr.cache[r.nodeName]) == 0 {
		delete(nr.cache, r.nodeName)
	}
}

func (nr *nodeIPv4Routes) visitRoutesForNode(nodename string, v func(nodenameIPv4Route)) {
	for cidr := range nr.cache[nodename] {
		v(nodenameIPv4Route{nodeName: nodename, dst: cidr})
	}
}
