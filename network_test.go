package core

import (
	"net"
	"testing"
)

func TestNetwork(t *testing.T) {
	_, ipv4Net, err := net.ParseCIDR("10.9.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ipv4Net)
}
