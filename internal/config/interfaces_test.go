package config

import (
	"reflect"
	"testing"
)

func TestRequiredInterfaces(t *testing.T) {
	// Mirrors the generated router config: a capture tun (its own device excluded, its LAN
	// iface included), two connections pinned to physical uplinks, and two direct egresses.
	n := &Node{
		Connections: []Connection{
			{Name: "Tun", Type: "tun", Interface: "dnlan0", LANIface: "br0"},
			{Name: "up", Type: "connect", Interface: "ppp1"},
			{Name: "down", Type: "connect", Interface: "nas10"},
			{Name: "dup", Type: "connect", Interface: "ppp1"}, // duplicate collapses
			{Name: "nopin", Type: "listen"},                   // no interface contributes nothing
		},
		Egresses: map[string]Egress{
			"ftth":     {Mode: "direct", ExtIface: "ppp1"}, // shared with a connection
			"starlink": {Mode: "direct", ExtIface: "nas10"},
			"warp":     {Mode: "warp"}, // no ext_iface
		},
	}
	got := n.RequiredInterfaces()
	want := []string{"br0", "nas10", "ppp1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RequiredInterfaces() = %v, want %v", got, want)
	}
}

func TestRequiredInterfacesExcludesTunDevice(t *testing.T) {
	// A plain tun with no LAN iface (e.g. the vps v2ray tun) contributes nothing: the node
	// creates that device itself, so there is nothing to wait for.
	n := &Node{Connections: []Connection{{Name: "V2Ray", Type: "tun", Interface: "dualnet0"}}}
	if got := n.RequiredInterfaces(); len(got) != 0 {
		t.Fatalf("RequiredInterfaces() = %v, want empty", got)
	}
}

func TestRequiredInterfacesEmpty(t *testing.T) {
	if got := (&Node{}).RequiredInterfaces(); len(got) != 0 {
		t.Fatalf("RequiredInterfaces() = %v, want empty", got)
	}
}
