package hostops

import (
	"reflect"
	"testing"
)

// Q25: every request type exposes only enum/validated fields; there is no
// field that could carry a command or path.
func TestNoFreeFormFields(t *testing.T) {
	forbidden := map[string]bool{"cmd": true, "command": true, "args": true, "script": true, "path": true, "shell": true, "exec": true, "env": true}
	for _, v := range []any{ServiceReq{}, FirewallReq{}, UpdateStageReq{}, UpdateCommitReq{}, Empty{}} {
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			if forbidden[rt.Field(i).Tag.Get("json")] {
				t.Errorf("%s has forbidden field %s", rt.Name(), rt.Field(i).Name)
			}
		}
	}
}

func TestValidation(t *testing.T) {
	if (ServiceReq{Service: "sshd"}).Validate() == nil {
		t.Fatal("unmanaged unit accepted")
	}
	if (ServiceReq{Service: "platformd; rm -rf /"}).Validate() == nil {
		t.Fatal("injection accepted")
	}
	if (UpdateStageReq{Channel: "stable; reboot", Version: "1.2.3"}).Validate() == nil {
		t.Fatal("bad channel accepted")
	}
	if (UpdateStageReq{Channel: "stable", Version: "../../x"}).Validate() == nil {
		t.Fatal("bad version accepted")
	}
	if (UpdateStageReq{Channel: "stable", Version: "2.1.0"}).Validate() != nil {
		t.Fatal("valid stage rejected")
	}
	if (FirewallReq{HTTPPort: 80, HTTPSPort: 443}).Validate() != nil {
		t.Fatal("valid firewall rejected")
	}
}
