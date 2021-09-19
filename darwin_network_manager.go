package core

import (
	"errors"
	"net"
	"os/exec"
	"strings"
)

type DarwinNetworkManager struct {
	sysdns     string
	netservice string
}

func NewDarwinNetworkManager() *DarwinNetworkManager {
	return &DarwinNetworkManager{}
}

func (nm *DarwinNetworkManager) setIPAddressAndEnable(tundev string, ip1 string) error {

	out, err := exec.Command("bash", "-c", "ifconfig "+tundev+" "+ip1+" "+ip1+" up").Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) setDnsServer(ip string, service string) error {

	out, err := exec.Command("bash", "-c", "networksetup -setdnsservers "+service+" "+ip).Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) removeDnsServer(service string) error {

	out, err := exec.Command("bash", "-c", "networksetup -setdnsservers "+service+" empty").Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) getNetServiceeDns() (string, string, error) {

	out, err := exec.Command("bash", "-c", "networksetup -listallnetworkservices").Output()
	if err != nil {
		return "", "", errors.New(err.Error() + "," + string(out))
	}

	a := strings.Split(string(out), "\n")

	for _, v := range a {
		v = strings.Trim(string(v), " \n\r\t")

		out, err := exec.Command("bash", "-c", "networksetup getinfo \""+v+"\"|grep \"IP address:\\W[1-9]\"").Output()
		index := strings.Index(string(out), "IP address: ")
		if err != nil || index == -1 {
			continue
		}

		out = out[index+len("IP address: "):]
		ip := net.ParseIP(strings.Trim(string(out), " \n\r\t"))

		if ip == nil {
			continue
		}

		out, err = exec.Command("bash", "-c", "networksetup -getdnsservers \""+v+"\"").Output()
		if err != nil {
			continue
		} else {
			dns := strings.Trim(string(out), " \n\r\t")
			a := strings.Split(dns, "\n")
			dnsip := net.ParseIP(a[0])
			if dnsip == nil {
				return v, "", nil
			} else {
				dns = strings.Replace(dns, "\n", " ", -1)
				return v, dns, nil
			}
		}
	}
	return "", "", errors.New("no net service have ip and dns")
}

func (nm *DarwinNetworkManager) addRoute(cidr string, gw string) error {

	out, err := exec.Command("bash", "-c", "route -n add -net "+cidr+" "+gw).Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *DarwinNetworkManager) delRoute(cidr string) error {

	out, err := exec.Command("bash", "-c", "route -n delete -net "+cidr).Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *DarwinNetworkManager) SetNetwork(device string, ip1 string, dns string) error {

	var err error

	plog.Infof("set tun device ip as %v", ip1)
	err = nm.setIPAddressAndEnable(device, ip1)
	if err != nil {
		return errors.New("set address fail," + err.Error())
	}

	nm.netservice, nm.sysdns, err = nm.getNetServiceeDns()

	plog.Infof("system network service:%v,dns:%v", nm.netservice, nm.sysdns)

	if err != nil {
		return errors.New("get system dns server fail," + err.Error())
	}

	plog.Infof("change network service %v dns to %v", nm.netservice, dns)
	err = nm.setDnsServer(dns, nm.netservice)

	if err != nil {
		return errors.New("set dns server fail," + err.Error())
	}

	routes := []string{"1/8", "2/7", "4/6", "8/5", "16/4", "32/3", "64/2", "128.0/1"}

	for _, route := range routes {
		plog.Info("add route ", route, "via", ip1)
		nm.delRoute(route)
		err = nm.addRoute(route, ip1)
		if err != nil {
			return errors.New("add route fail," + err.Error())
		}
	}
	return nil
}

func (nm *DarwinNetworkManager) RestoreNetwork() {

	plog.Infof("restore network service %v", nm.netservice)
	nm.removeDnsServer(nm.netservice)
	if nm.sysdns != "" {
		plog.Infof("set service %v dns to %v", nm.netservice, nm.sysdns)
		nm.setDnsServer(nm.sysdns, nm.netservice)
	}
}
