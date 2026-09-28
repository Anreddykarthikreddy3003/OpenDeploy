package builder

import "testing"

func TestCSVField(t *testing.T) {
	for in, want := range map[string]string{
		"dest=/tmp/a/out.tar":   "dest=/tmp/a/out.tar",
		"dest=/tmp/a,b/out.tar": `"dest=/tmp/a,b/out.tar"`,
		`src=/tmp/q"x,y`:        `"src=/tmp/q""x,y"`,
	} {
		if got := csvField(in); got != want {
			t.Errorf("csvField(%q) = %q, want %q", in, got, want)
		}
	}
}
