package core

import (
	"errors"
	"net"
	"strings"
	"sync"
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
		return errors.New("setIPAddressAndEnable fail," + err.Error() + "," + string(out))
	}

	// out, err = ExecuteCommand("bash", "-c", "ifconfig "+tundev+" inet6 add 2001:2323:2323:2323:2323:2323:2323:2323/128 up")
	// if err != nil {
	// 	return errors.New(err.Error() + "," + string(out))
	// }

	return nil
}

func (nm *DarwinNetworkManager) setDnsServer(ip string, service string) error {

	out, err := ExecuteCommand("bash", "-c", "networksetup -setdnsservers "+service+" "+ip)

	if err != nil {
		return errors.New("setDnsServer fail," + err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) flushDns() error {

	out, err := ExecuteCommand("bash", "-c", "dscacheutil -flushcache")

	if err != nil {
		return errors.New("flushDns fail," + err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) removeDnsServer(service string) error {

	out, err := ExecuteCommand("bash", "-c", "networksetup -setdnsservers "+service+" empty")

	if err != nil {
		return errors.New("removeDnsServer fail," + err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) getDefaultGateway() (string, error) {
	out, err := ExecuteCommand("bash", "-c", "route -n get default |grep gateway")
	if err != nil {
		return "", errors.New("getDefaultGateway fail," + err.Error() + "," + string(out))
	}

	gateway := strings.Replace(string(out), "gateway: ", "", -1)
	return strings.Trim(gateway, " \n\r\t"), nil
}

func (nm *DarwinNetworkManager) getDefaultNetService(gw string) (string, error) {

	out, err := ExecuteCommand("bash", "-c", "networksetup -listallnetworkservices")
	if err != nil {
		return "", errors.New("getDefaultNetService fail," + err.Error() + "," + string(out))
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

		if router != gw {
			continue
		} else {
			return v, nil
		}
	}
	return "", errors.New("getDefaultNetService fail,no net service found")
}

func (nm *DarwinNetworkManager) getNetServiceDns(service string) (string, error) {

	out, err := ExecuteCommand("bash", "-c", "networksetup -getdnsservers \""+service+"\"")

	if err != nil {
		return "", errors.New("getNetServiceDns fail," + err.Error() + "," + string(out))
	}

	dns := strings.Trim(string(out), " \n\r\t")
	a := strings.Split(dns, "\n")
	dnsip := net.ParseIP(a[0])
	if dnsip == nil {
		return "", nil
	} else {
		dns = strings.Replace(dns, "\n", " ", -1)
		return dns, nil
	}
}

func (nm *DarwinNetworkManager) addRoute(cidr string, gw string) error {

	//sudo route -n add -inet6 2606:4700:4700::1111/128 2001::2323:2323:2323:2323

	out, err := ExecuteCommand("bash", "-c", "route -n add -net "+cidr+" "+gw)

	if err != nil {
		return errors.New("addRoute fail," + err.Error() + "," + string(out))
	}
	return err

}

func (nm *DarwinNetworkManager) delRoute(cidr string) error {

	out, err := ExecuteCommand("bash", "-c", "route -n delete -net "+cidr)

	if err != nil {
		return errors.New("delRoute fail," + err.Error() + "," + string(out))
	}
	return err

}

func (nm *DarwinNetworkManager) GetLocalIP() (string, error) {

	var err error
	nm.defaultGateway, err = nm.getDefaultGateway()

	if err != nil {
		return "", err
	}

	nm.netservice, err = nm.getDefaultNetService(nm.defaultGateway)

	if err != nil {
		return "", err
	}

	return nm.getLocalIp(nm.netservice)
}

func (nm *DarwinNetworkManager) getLocalIp(service string) (string, error) {

	out, err := ExecuteCommand("bash", "-c", "networksetup getinfo \""+service+"\"|grep \"IP address:\\W[1-9]\"")

	if err != nil {
		return "", errors.New("getLocalIp fail," + err.Error() + "," + string(out))
	}

	localip := strings.Replace(string(out), "IP address: ", "", -1)
	localip = strings.Trim(localip, " \n\r\t")

	return localip, nil

}

func (nm *DarwinNetworkManager) disableIpv6() error {

	out, err := ExecuteCommand("bash", "-c", "networksetup -setv6off Wi-Fi")

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}

	out1, err := ExecuteCommand("bash", "-c", "networksetup -setv6off Ethernet")

	if err != nil {
		return errors.New(err.Error() + "," + string(out1))
	}

	return nil
}

func (nm *DarwinNetworkManager) SetNetwork(device string, gateway string, remoteIp string, dns string, routes []string) error {

	nm.gateway = gateway
	nm.remoteIp = remoteIp

	go nm.disableIpv6()

	var err error

	if nm.defaultGateway == "" {
		nm.defaultGateway, err = nm.getDefaultGateway()
		if err != nil {
			return err
		}
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

	wg := sync.WaitGroup{}

	ech := make(chan error, len(routes))

	defer close(ech)

	for _, route := range routes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			plog.Info("add route ", route, " via ", gateway)
			//nm.delRoute(route)
			err := nm.addRoute(route, gateway)

			if err != nil {
				ech <- errors.New("add route fail," + err.Error())
			}
		}()
	}

	wg.Wait()

	select {
	case err = <-ech:
		return err
	default:
	}

	if nm.netservice == "" {
		nm.netservice, err = nm.getDefaultNetService(nm.defaultGateway)

		if err != nil {
			return err
		}
	}

	nm.sysdns, err = nm.getNetServiceDns(nm.netservice)

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

	go nm.flushDns()

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
		go nm.delRoute(nm.remoteIp)
	}

	if nm.netservice != "" {
		go nm.removeDnsServer(nm.netservice)
		if nm.sysdns != "" {
			plog.Infof("set service %v dns to %v", nm.netservice, nm.sysdns)
			go nm.setDnsServer(nm.sysdns, nm.netservice)
		}
	}
}
