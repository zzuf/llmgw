package acl

import "testing"

func TestACLMatrix(t *testing.T) {
	cases := []struct {
		name, remote string
		ips, keys    []string
		key          string
		ok           bool
	}{
		{"none", "192.168.0.9:12", nil, nil, "dummy", true},
		{"ip only", "192.168.0.9:12", []string{"192.168.0.0/24"}, nil, "dummy", true},
		{"ip reject", "10.0.0.2:12", []string{"192.168.0.0/24"}, nil, "", false},
		{"key only", "10.0.0.2:12", nil, []string{"a"}, "a", true},
		{"key reject", "10.0.0.2:12", nil, []string{"a"}, "dummy", false},
		{"and", "192.168.0.9:12", []string{"192.168.0.0/24"}, []string{"a"}, "a", true},
		{"and ip reject", "10.0.0.2:12", []string{"192.168.0.0/24"}, []string{"a"}, "a", false},
		{"and key reject", "192.168.0.9:12", []string{"192.168.0.0/24"}, []string{"a"}, "", false},
		{"invalid", "bogus", []string{"0.0.0.0/0"}, nil, "", false},
		{"ipv6", "[::1]:12", []string{"::1/128"}, nil, "", true},
		{"mapped", "[::ffff:127.0.0.1]:12", []string{"127.0.0.1/32"}, nil, "", true},
		{"single", "127.0.0.1:12", []string{"127.0.0.1"}, nil, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := SourceIP(c.remote)
			if got := Allowed(ip, c.ips, c.keys, c.key); got != c.ok {
				t.Fatalf("got %v want %v", got, c.ok)
			}
		})
	}
}
