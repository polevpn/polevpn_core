package core

import (
	"errors"
	"net"
	"strings"
)

type DarwinNetworkManager struct {
	sysdns         string
	netservice     string
	defaultGateway string
	remoteIp       string
	gateway        string
}

func NewDarwinNetworkManager() *DarwinNetworkManager {
	return &DarwinNetworkManager{}
}

func (nm *DarwinNetworkManager) setIPAddressAndEnable(tundev string, ip1 string) error {

	out, err := ExecuteCommand("bash", "-c", "ifconfig "+tundev+" "+ip1+" "+ip1+" up")
	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) setDnsServer(ip string, service string) error {

	out, err := ExecuteCommand("bash", "-c", "networksetup -setdnsservers "+service+" "+ip)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) flushDns() error {

	out, err := ExecuteCommand("bash", "-c", "dscacheutil -flushcache")

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) removeDnsServer(service string) error {

	out, err := ExecuteCommand("bash", "-c", "networksetup -setdnsservers "+service+" empty")

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) getDefaultGateway() (string, error) {
	out, err := ExecuteCommand("bash", "-c", "route -n get default |grep gateway")
	if err != nil {
		return "", err
	}

	gateway := strings.Replace(string(out), "gateway: ", "", -1)
	return strings.Trim(gateway, " \n\r\t"), nil
}

func (nm *DarwinNetworkManager) getNetServiceeDns() (string, string, error) {

	out, err := ExecuteCommand("bash", "-c", "networksetup -listallnetworkservices")
	if err != nil {
		return "", "", errors.New(err.Error() + "," + string(out))
	}

	a := strings.Split(string(out), "\n")

	for _, v := range a {
		v = strings.Trim(string(v), " \n\r\t")

		out, err := ExecuteCommand("bash", "-c", "networksetup getinfo \""+v+"\"|grep \"Router:\\W[1-9]\"")

		if err != nil {
			continue
		}

		router := strings.Replace(string(out), "Router: ", "", -1)
		router = strings.Trim(router, " \n\r\t")

		if router != nm.defaultGateway {
			continue
		}

		out, err = ExecuteCommand("bash", "-c", "networksetup -getdnsservers \""+v+"\"")
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

	out, err := ExecuteCommand("bash", "-c", "route -n add -net "+cidr+" "+gw)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *DarwinNetworkManager) delRoute(cidr string) error {

	out, err := ExecuteCommand("bash", "-c", "route -n delete -net "+cidr)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *DarwinNetworkManager) SetNetwork(device string, gateway string, remoteIp string, dns string, routes []string) error {

	nm.gateway = gateway
	nm.remoteIp = remoteIp

	var err error

	nm.defaultGateway, err = nm.getDefaultGateway()
	if err != nil {
		return err
	}

	plog.Infof("set tun device ip as %v", gateway)
	err = nm.setIPAddressAndEnable(device, gateway)
	if err != nil {
		return errors.New("set address fail," + err.Error())
	}

	plog.Info("add route ", remoteIp, " via ", nm.defaultGateway)
	nm.delRoute(nm.remoteIp)
	err = nm.addRoute(nm.remoteIp, nm.defaultGateway)

	if err != nil {
		return errors.New("add route fail," + err.Error())
	}

	//routes := []string{"8.8.8.8/32"}

	for _, route := range routes {
		plog.Info("add route ", route, " via ", gateway)
		nm.delRoute(route)
		err = nm.addRoute(route, gateway)
		if err != nil {
			return errors.New("add route fail," + err.Error())
		}
	}

	nm.netservice, nm.sysdns, err = nm.getNetServiceeDns()

	plog.Infof("system network service:%v,dns:%v", nm.netservice, nm.sysdns)

	if err != nil {
		return errors.New("get system dns server fail," + err.Error())
	}

	if dns != "" {
		plog.Infof("change network service %v dns to %v", nm.netservice, dns)
		err = nm.setDnsServer(dns, nm.netservice)
	}

	if err != nil {
		return errors.New("set dns server fail," + err.Error())
	}

	err = nm.flushDns()

	if err != nil {
		plog.Error("flush dns fail,", err)
	}

	return nil
}

func (nm *DarwinNetworkManager) RefreshDefaultGateway() error {
	var err error
	nm.defaultGateway, err = nm.getDefaultGateway()
	if err != nil {
		return err
	}

	nm.delRoute(nm.remoteIp)

	return nm.addRoute(nm.remoteIp, nm.defaultGateway)

}

func (nm *DarwinNetworkManager) RestoreNetwork() {

	plog.Infof("restore network service %v", nm.netservice)
	if nm.remoteIp != "" {
		nm.delRoute(nm.remoteIp)
	}

	if nm.netservice != "" {
		nm.removeDnsServer(nm.netservice)
		if nm.sysdns != "" {
			plog.Infof("set service %v dns to %v", nm.netservice, nm.sysdns)
			nm.setDnsServer(nm.sysdns, nm.netservice)
		}
	}
}
