package netschema

import "testing"

// validNet returns a minimal network that passes validate(): two nodes and one link over a
// named http protocol. Each negative case below mutates a fresh copy.
func validNet() *Network {
	return &Network{
		Protocols: map[string]ProtocolSpec{"web": {Transport: "http"}},
		Nodes:     map[string]Node{"a": {}, "b": {IP: "1.2.3.4"}},
		Links:     []Link{{Name: "a-up", Dialer: "a", Acceptor: "b", Dataflow: "to-acceptor", Protocol: "web", Port: 80}},
	}
}

func TestValidateBaseline(t *testing.T) {
	if err := validNet().validate(); err != nil {
		t.Fatalf("baseline should be valid: %v", err)
	}
	// A fully-customized http protocol is valid.
	n := validNet()
	n.Protocols["web"] = ProtocolSpec{
		Transport: "http", Cipher: "chacha4", Warpped: true,
		UploadPath: "/u", DownloadPath: "/d", Host: "h", UserAgent: "ua", IDHeader: "X-Tag",
		Headers: map[string]string{"X-K": "v"},
	}
	if err := n.validate(); err != nil {
		t.Fatalf("customized http protocol should be valid: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Network){
		"unknown protocol reference": func(n *Network) { n.Links[0].Protocol = "nope" },
		"empty protocol reference":   func(n *Network) { n.Links[0].Protocol = "" },
		"bad transport":              func(n *Network) { n.Protocols["web"] = ProtocolSpec{Transport: "quic"} },
		"http field on udp":          func(n *Network) { n.Protocols["web"] = ProtocolSpec{Transport: "udp", UploadPath: "/x"} },
		"warpped on udp":             func(n *Network) { n.Protocols["web"] = ProtocolSpec{Transport: "udp", Warpped: true} },
	}
	for name, mutate := range cases {
		n := validNet()
		mutate(n)
		if err := n.validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestValidateDeploy(t *testing.T) {
	// A build recipe plus an ssh deploy and a k8s deploy validate cleanly.
	n := validNet()
	n.Builds = map[string]BuildSpec{"server": {Arch: "amd64"}, "modem": {Arch: "arm/v7", Upx: true}}
	setDeploy(n, "a", &DeploySpec{Mode: "ssh", Build: "modem", Daemonize: "none"})
	setDeploy(n, "b", &DeploySpec{Mode: "k8s", Build: "server", Image: "img:latest"})
	if err := n.validate(); err != nil {
		t.Fatalf("deploy baseline should be valid: %v", err)
	}
}

func TestValidateDeployRejects(t *testing.T) {
	cases := map[string]func(*Network){
		"bad build arch":       func(n *Network) { n.Builds["x"] = BuildSpec{Arch: "riscv"} },
		"deploy missing build": func(n *Network) { setDeploy(n, "a", &DeploySpec{Mode: "ssh"}) },
		"deploy unknown build": func(n *Network) { setDeploy(n, "a", &DeploySpec{Mode: "ssh", Build: "nope"}) },
		"bad mode":             func(n *Network) { setDeploy(n, "a", &DeploySpec{Mode: "carrier", Build: "server"}) },
		"bad daemonize":        func(n *Network) { setDeploy(n, "a", &DeploySpec{Mode: "ssh", Build: "server", Daemonize: "runit"}) },
		"ssh sets k8s field":   func(n *Network) { setDeploy(n, "a", &DeploySpec{Mode: "ssh", Build: "server", Image: "img"}) },
		"k8s missing image":    func(n *Network) { setDeploy(n, "b", &DeploySpec{Mode: "k8s", Build: "server"}) },
		"k8s sets ssh field": func(n *Network) {
			setDeploy(n, "b", &DeploySpec{Mode: "k8s", Build: "server", Image: "img", Host: "h"})
		},
		"bad method": func(n *Network) {
			setDeploy(n, "b", &DeploySpec{Mode: "k8s", Build: "server", Image: "img", Method: "scp"})
		},
		"bad manifest": func(n *Network) {
			setDeploy(n, "b", &DeploySpec{Mode: "k8s", Build: "server", Image: "img", Manifest: "daemonset"})
		},
	}
	for name, mutate := range cases {
		n := validNet()
		n.Builds = map[string]BuildSpec{"server": {Arch: "amd64"}}
		mutate(n)
		if err := n.validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// setDeploy attaches a deploy block to a node in the (value-typed) Nodes map.
func setDeploy(n *Network, node string, d *DeploySpec) {
	x := n.Nodes[node]
	x.Deploy = d
	n.Nodes[node] = x
}
