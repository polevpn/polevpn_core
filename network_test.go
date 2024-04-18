package core

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestNetwork(t *testing.T) {
	_, ipv4Net, err := net.ParseCIDR("10.9.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ipv4Net)
}

func TestGetInterfaceList(t *testing.T) {

	out, err := GetInterfaceList()

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(out)

	cmd := "netsh interface ip set dns \"" + out[4] + "\" static 1.1.1.2 primary"
	fmt.Println(cmd)
	args := strings.Split(cmd, " ")
	out1, err := ExecuteCommand(args[0], args[1:]...)

	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(out1))
}

func GetInterfaceList() ([]string, error) {

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	outStr := make([]string, 0)

	for _, i := range interfaces {
		byName, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}
		addresses, err := byName.Addrs()
		if err != nil {
			return nil, err
		}
		for _, v := range addresses {
			if strings.Contains(v.String(), ":") {
				continue
			}

			if strings.Contains(v.String(), "169.") || strings.Contains(v.String(), "127.") {
				continue
			}

			_, _, err := net.ParseCIDR(v.String())
			if err != nil {
				continue
			}
			outStr = append(outStr, i.Name)
		}
	}

	if len(outStr) == 0 {
		return nil, errors.New("can not find any interface")
	}

	return outStr, nil
}
