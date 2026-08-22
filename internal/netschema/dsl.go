package netschema

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file holds the one-line string DSLs the schema uses for links and routes, kept separate
// from the domain types in schema.go. Both are pure string→struct parsers (no cross-references;
// name/existence validation happens later in validate()), and are unit-tested in dsl_test.go.

// Links decodes the `links:` mapping, whose every value is a one-line link definition:
//
//	<name>: <dialer>[.<conn>] <arrow> <acceptor>[.<conn>] (<protocol>, <port>)
//
// The dialer is ALWAYS on the left; the arrow (a whitespace-separated token) encodes direction,
// `multiple`, and the id-setter tun (see parseArrow): `->` the dialer sends (to-acceptor), `<-`
// the acceptor sends (to-dialer); doubling the point (`->>`/`<<-`) adds `multiple`; embedding a
// tun connection name (`-utun9>`/`<utun9-`) makes the acceptor assign that dialer tun's owner
// id; combine as `-utun9>>`/`<<utun9-`. A `node.conn` binds that connection.
type Links []Link

func (ls *Links) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("netschema: links must be a mapping of name -> definition")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		l, err := parseLink(node.Content[i].Value, node.Content[i+1].Value)
		if err != nil {
			return err
		}
		*ls = append(*ls, l)
	}
	return nil
}

// parseArrow decodes a link arrow token into (dataflow, multiple, idSetter). `>` points at the
// acceptor (to-acceptor), `<` at the dialer (to-dialer); doubling the point (`>>`/`<<`) sets
// multiple; any name between the `-` and the point is the id-setter tun (empty = none):
//
//	->  ->>  -utun9>  -utun9>>        (to-acceptor)
//	<-  <<-  <utun9-  <<utun9-        (to-dialer)
func parseArrow(tok string) (dataflow string, multiple bool, idSetter string, ok bool) {
	switch {
	case strings.Contains(tok, ">"): // to-acceptor: -[name]>[>]
		if !strings.HasPrefix(tok, "-") {
			return "", false, "", false
		}
		body := tok[1:]
		switch {
		case strings.HasSuffix(body, ">>"):
			multiple, body = true, body[:len(body)-2]
		case strings.HasSuffix(body, ">"):
			body = body[:len(body)-1]
		default:
			return "", false, "", false
		}
		dataflow, idSetter = toAcceptor, body
	case strings.Contains(tok, "<"): // to-dialer: [<]<[name]-
		if !strings.HasSuffix(tok, "-") {
			return "", false, "", false
		}
		body := tok[:len(tok)-1]
		switch {
		case strings.HasPrefix(body, "<<"):
			multiple, body = true, body[2:]
		case strings.HasPrefix(body, "<"):
			body = body[1:]
		default:
			return "", false, "", false
		}
		dataflow, idSetter = toDialer, body
	default:
		return "", false, "", false
	}
	if strings.ContainsAny(idSetter, "<>-.") { // the name (if any) must be a bare token
		return "", false, "", false
	}
	return dataflow, multiple, idSetter, true
}

// parseLink parses one link line (see Links); name is the mapping key.
func parseLink(name, def string) (Link, error) {
	l := Link{Name: name}
	open := strings.IndexByte(def, '(')
	closeParen := strings.LastIndexByte(def, ')')
	if open < 0 || closeParen < open {
		return Link{}, fmt.Errorf("netschema: link %q: want `dialer[.conn] <arrow> acceptor[.conn] (protocol, port)`", name)
	}
	// Head is three whitespace-separated tokens: dialer, arrow, acceptor. Requiring spaces keeps
	// the arrow unambiguous even when node/connection names contain hyphens.
	fields := strings.Fields(def[:open])
	if len(fields) != 3 {
		return Link{}, fmt.Errorf("netschema: link %q: want `dialer <arrow> acceptor` (spaces around the arrow)", name)
	}
	dataflow, multiple, idSetter, ok := parseArrow(fields[1])
	if !ok {
		return Link{}, fmt.Errorf("netschema: link %q: bad arrow %q (-> <- ->> <<- -tun> <tun- …)", name, fields[1])
	}
	l.Dataflow, l.Multiple, l.IDSetter = dataflow, multiple, idSetter
	l.Dialer, l.DialerSource = splitNodeSource(fields[0])
	l.Acceptor, l.AcceptorSource = splitNodeSource(fields[2])
	if l.Dialer == "" || l.Acceptor == "" {
		return Link{}, fmt.Errorf("netschema: link %q: needs a dialer and an acceptor", name)
	}
	parts := splitTrim(def[open+1:closeParen], ",")
	if len(parts) != 2 {
		return Link{}, fmt.Errorf("netschema: link %q: want exactly (protocol, port)", name)
	}
	l.Protocol = parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return Link{}, fmt.Errorf("netschema: link %q: bad port %q", name, parts[1])
	}
	l.Port = port
	return l, nil
}

// Branches decodes the ordered `routes:` mapping, whose keys are condition names (or `default`)
// and whose values are one-line routes:
//
//	<condition>: <up-link> > … > (<egress>) > <down-link> > …
//
// Tokens before the parenthesized (egress) are the up-links (origin→gateway) in order; tokens
// after are the down-links (gateway→origin); a lone egress (parenthesized or bare) is a local
// exit. The gateway is inferred as the terminus of the last up-link. Order is preserved (first
// match wins); the `default` key (no condition) is the always-last catch-all.
type Branches []Branch

func (bs *Branches) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("netschema: routes must be a mapping of condition -> route")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		br, err := parseBranch(node.Content[i].Value, node.Content[i+1])
		if err != nil {
			return err
		}
		*bs = append(*bs, br)
	}
	return nil
}

// parseBranch parses one route line; cond is the mapping key (a condition name, or "default").
func parseBranch(cond string, val *yaml.Node) (Branch, error) {
	if val.Kind != yaml.ScalarNode {
		return Branch{}, fmt.Errorf("netschema: route %q must be a string (wrap the egress in parentheses, e.g. (ftth))", cond)
	}
	var br Branch
	if cond != "default" {
		br.When = []string{cond}
	}
	tokens := splitTrim(val.Value, ">")
	if len(tokens) == 0 {
		return Branch{}, fmt.Errorf("netschema: route %q is empty", cond)
	}
	egressIdx := -1
	for i, t := range tokens {
		if strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
			if egressIdx >= 0 {
				return Branch{}, fmt.Errorf("netschema: route %q has more than one (egress)", cond)
			}
			egressIdx = i
		}
	}
	if egressIdx < 0 {
		if len(tokens) != 1 {
			return Branch{}, fmt.Errorf("netschema: route %q must wrap its (egress) in parentheses", cond)
		}
		br.Egress = tokens[0] // a lone bare token is the (local) egress
		return br, nil
	}
	br.Egress = strings.TrimSpace(tokens[egressIdx][1 : len(tokens[egressIdx])-1])
	if egressIdx > 0 {
		br.Up = append([]string{}, tokens[:egressIdx]...)
	}
	if egressIdx < len(tokens)-1 {
		br.Down = append([]string{}, tokens[egressIdx+1:]...)
	}
	return br, nil
}

// splitNodeSource splits "node.conn" into its parts ("node" -> ("node", "")).
func splitNodeSource(s string) (node, source string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// splitTrim splits s on sep, trims each element, and drops empties.
func splitTrim(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
