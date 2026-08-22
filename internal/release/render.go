package release

import (
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"strings"
	"text/template"
)

//go:embed templates/*
var tmplFS embed.FS

// tmpl is the parsed template set; funcs are shared by every template.
var tmpl = template.Must(template.New("release").Funcs(template.FuncMap{
	"indent": indent,
}).ParseFS(tmplFS, "templates/*.tmpl"))

// Render renders the plan into its artifacts: build.sh + deploy.sh (0755), a thin runtime
// Dockerfile (only when there are k8s image builds), and one <node>.k8s.yaml per k8s node
// (0644). Build (create artifacts) and deploy (ship them) are separate scripts, mirroring the
// schema's builds/deploy split. It touches no filesystem and never emits the PSK, so it is
// golden-file testable.
func (p *Plan) Render() ([]Artifact, error) {
	var arts []Artifact
	for _, name := range []string{"build.sh", "deploy.sh"} {
		data, err := render(name+".tmpl", p)
		if err != nil {
			return nil, err
		}
		arts = append(arts, Artifact{Name: name, Mode: 0o755, Data: data})
	}

	if len(p.Docker) > 0 {
		df, err := tmplFS.ReadFile("templates/Dockerfile.release")
		if err != nil {
			return nil, fmt.Errorf("release: read Dockerfile template: %w", err)
		}
		arts = append(arts, Artifact{Name: "Dockerfile.release", Mode: 0o644, Data: df})
	}

	for _, k := range p.K8sNodes {
		m, err := render("k8s.yaml.tmpl", k)
		if err != nil {
			return nil, err
		}
		arts = append(arts, Artifact{Name: k.Manifest, Mode: 0o644, Data: m})
	}
	return arts, nil
}

func render(name string, data any) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return nil, fmt.Errorf("release: render %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// indent prefixes every non-empty line of s with n spaces (blank lines stay blank), for
// embedding a YAML document inside a block scalar.
func indent(n int, s string) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = pad + l
		}
	}
	return strings.Join(lines, "\n")
}

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
