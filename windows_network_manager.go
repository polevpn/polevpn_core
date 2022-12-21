package core

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

type WindowsNetworkManager struct {
	defaultGateway string
	remoteIp       string
	gateway        string
	localIp        string
}

func NewWindowsNetworkManager() *WindowsNetworkManager {
	return &WindowsNetworkManager{}
}

func (nm *WindowsNetworkManager) setIPAddressAndEnable(tundev string, ip1 string) error {

	cmd := "netsh interface ip set address name=\"" + tundev + "\" source=static addr=" + ip1 + " gateway=none"
	args := strings.Split(cmd, " ")

	out, err := ExecuteCommand(args[0], args[1:]...)
	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *WindowsNetworkManager) setDnsServer(ip string, device string) error {

	cmd := "netsh interface ip set dns \"" + device + "\" static " + ip
	args := strings.Split(cmd, " ")

	out, err := ExecuteCommand(args[0], args[1:]...)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *WindowsNetworkManager) flushDns() error {

	cmd := "ipconfig /flushdns"
	args := strings.Split(cmd, " ")

	out, err := ExecuteCommand(args[0], args[1:]...)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *WindowsNetworkManager) setInterfaceMetric(device string, mertic string) error {

	cmd := "powershell -nologo -noprofile Set-NetIPInterface -InterfaceAlias '" + device + "' -InterfaceMetric " + mertic
	args := strings.Split(cmd, " ")

	out, err := ExecuteCommand(args[0], args[1:]...)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *WindowsNetworkManager) restoreDnsServer() error {

	return nil
}

func (nm *WindowsNetworkManager) getDefaultGatewayAndLocalIP() (string, string, error) {

	out, err := ExecuteCommand("route", "print")
	if err != nil {
		return "", "", errors.New(err.Error() + "," + string(out))
	}
	reg := regexp.MustCompile(`.*?0.0.0.0.*?0.0.0.0.*?(([0-9]{1,3}[\.]){3}[0-9]{1,3}).*?(([0-9]{1,3}[\.]){3}[0-9]{1,3})`)
	result := reg.FindStringSubmatch(string(out))
	if len(result) > 4 {
		return result[1], result[3], nil
	}
	return "", "", errors.New("cann't find any default gateway")
}

func (nm *WindowsNetworkManager) getInfNameByIP(ip string) (string, error) {

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, i := range interfaces {
		byName, err := net.InterfaceByName(i.Name)
		if err != nil {
			return "", err
		}
		addresses, err := byName.Addrs()
		if err != nil {
			return "", err
		}
		for _, v := range addresses {
			ip1, _, err := net.ParseCIDR(v.String())
			if err != nil {
				continue
			}
			if ip == ip1.String() {
				return i.Name, nil
			}
		}
	}
	return "", errors.New("can't find any interface by ip")
}

func (nm *WindowsNetworkManager) addRoute(cidr string, gw string, ifce string) error {
	cmd := "netsh interface ip add route prefix=" + cidr + " interface=\"" + ifce + "\" store=active nexthop=" + gw
	args := strings.Split(cmd, " ")
	out, err := ExecuteCommand(args[0], args[1:]...)
	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err
}

func (nm *WindowsNetworkManager) delRoute(cidr string) error {

	out, err := ExecuteCommand("route", "delete", cidr)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *WindowsNetworkManager) clearRoute() error {

	out, err := ExecuteCommand("route", "delete", "*", nm.gateway)
	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *WindowsNetworkManager) SetNetwork(device string, ip string, remoteIp string, dns string, routes []string) error {

	nm.remoteIp = remoteIp

	var err error

	nm.defaultGateway, nm.localIp, err = nm.getDefaultGatewayAndLocalIP()
	if err != nil {
		return err
	}

	localDevice, err := nm.getInfNameByIP(nm.localIp)

	if err != nil {
		return err
	}

	plog.Infof("set tun device %v ip as %v", device, ip)

	err = nm.setIPAddressAndEnable(device, ip)

	if err != nil {
		return errors.New("set address fail," + err.Error())
	}

	err = nm.setInterfaceMetric(localDevice, "20")

	if err != nil {
		plog.Errorf("set interface %v mertic fail,%v", localDevice, err)
	}

	err = nm.setInterfaceMetric(device, "10")

	if err != nil {
		plog.Errorf("set interface %v mertic fail,%v", device, err)
	}

	err = nm.flushDns()

	if err != nil {
		plog.Errorf("flushdns fail,%v", err)
	}

	_, network, err := net.ParseCIDR(ip + "/30")
	if err != nil {
		return err
	}
	var gateway = network.IP.String()

	if ip == gateway {
		first := network.IP.To4()
		first[3] = first[3] + 1
		gateway = first.String()
	}

	nm.gateway = gateway
	if dns != "" {
		plog.Infof("change network dns to %v", dns)
		err = nm.setDnsServer(dns, device)
		if err != nil {
			return errors.New("set dns fail," + err.Error())
		}
	}

	plog.Info("add route ", nm.remoteIp, " via ", nm.defaultGateway)
	nm.delRoute(nm.remoteIp)
	err = nm.addRoute(nm.remoteIp+"/32", nm.defaultGateway, localDevice)

	if err != nil {
		return errors.New("add route fail," + err.Error())
	}

	for _, route := range routes {
		plog.Info("add route ", route, " via ", gateway)
		nm.delRoute(route)
		err = nm.addRoute(route, gateway, device)
		if err != nil {
			return errors.New("add route fail," + err.Error())
		}
	}
	return nil
}

func (nm *WindowsNetworkManager) RefreshDefaultGateway() error {

	var err error
	nm.defaultGateway, nm.localIp, err = nm.getDefaultGatewayAndLocalIP()
	if err != nil {
		return err
	}

	localDevice, err := nm.getInfNameByIP(nm.localIp)

	if err != nil {
		return err
	}

	nm.delRoute(nm.remoteIp)

	return nm.addRoute(nm.remoteIp+"/32", nm.defaultGateway, localDevice)
}

func (nm *WindowsNetworkManager) RestoreNetwork() {

	plog.Infof("restore network service")
	nm.clearRoute()
	nm.delRoute(nm.remoteIp)
	nm.restoreDnsServer()
}
