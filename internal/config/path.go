package config

import (
	"os"
	"os/user"
	"path/filepath"
)

// ResolveConfigPath returns the config file to use and whether one was found. An
// explicit path is used as-is; otherwise the default search order is tried.
func ResolveConfigPath(explicit string) (string, bool) {
	if explicit != "" {
		return explicit, true
	}
	for _, p := range defaultConfigPaths() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	return "", false
}

func defaultConfigPaths() []string {
	var out []string
	if home := userConfigHome(); home != "" {
		out = append(out, filepath.Join(home, "dualnet", "node.yaml"))
	}
	return append(out, "/etc/dualnet/node.yaml")
}

// userConfigHome returns the invoking user's config dir. Under sudo it resolves the
// original user's home (not root's), so ~/.config/dualnet works.
func userConfigHome() string {
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil && u.HomeDir != "" {
			return filepath.Join(u.HomeDir, ".config")
		}
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return x
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config")
	}
	return ""
}
