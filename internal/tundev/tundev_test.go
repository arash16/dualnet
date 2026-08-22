package tundev

import "testing"

func TestNormalizeDarwinTunName(t *testing.T) {
	cases := map[string]string{
		"":         "utun",  // auto
		"utun":     "utun",  // auto (explicit)
		"utun0":    "utun0", // specific
		"utun5":    "utun5",
		"dualnet0": "utun", // Linux-style name -> auto
		"tun0":     "utun",
		"utunX":    "utun", // malformed -> auto
		"en0":      "utun",
	}
	for in, want := range cases {
		if got := normalizeDarwinTunName(in); got != want {
			t.Errorf("normalizeDarwinTunName(%q) = %q, want %q", in, got, want)
		}
	}
}
