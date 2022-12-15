package core

import (
	"errors"
	"strings"
)

type LinuxNetworkManager struct {
	defaultGateway string
	remoteIp       string
	gateway        string
}

func NewLinuxNetworkManager() *LinuxNetworkManager {
	return &LinuxNetworkManager{}
}

func (nm *LinuxNetworkManager) setIPAddressAndEnable(tundev string, ip1 string) error {

	var out []byte
	var err error

	out, err = ExecuteCommand("bash", "-c", "sudo ip addr flush dev "+tundev)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}

	out, err = ExecuteCommand("bash", "-c", "ip addr add dev "+tundev+" local "+ip1+" peer "+ip1)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}

	out, err = ExecuteCommand("bash", "-c", "ip link set "+tundev+" up")
	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *LinuxNetworkManager) setDnsServer(ip string) error {

	out, err := ExecuteCommand("bash", "-c", `echo "nameserver `+ip+`" |tee /etc/resolv.conf`)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *LinuxNetworkManager) restoreDnsServer() error {

	out, err := ExecuteCommand("bash", "-c", `systemctl restart systemd-resolved`)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *LinuxNetworkManager) getDefaultGateway() (string, error) {
	out, err := ExecuteCommand("bash", "-c", `ip route |grep default|grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}"|head -1`)
	if err != nil {
		return "", err
	}
	return strings.Trim(string(out), " \n\r\t"), nil
}

func (nm *LinuxNetworkManager) addRoute(cidr string, gw string) error {
	out, err := ExecuteCommand("bash", "-c", "ip route add "+cidr+" via "+gw)
	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err
}

func (nm *LinuxNetworkManager) delRoute(cidr string) error {

	out, err := ExecuteCommand("bash", "-c", "ip route del "+cidr)

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *LinuxNetworkManager) SetNetwork(device string, gateway string, remoteIp string, dns string, routes []string) error {

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

	if dns != "" {
		plog.Infof("change network dns to %v", dns)
		err = nm.setDnsServer(dns)
	}

	if err != nil {
		return errors.New("set dns fail," + err.Error())
	}

	plog.Info("add route ", nm.remoteIp, " via ", nm.defaultGateway)
	nm.delRoute(nm.remoteIp)
	err = nm.addRoute(nm.remoteIp, nm.defaultGateway)

	if err != nil {
		return errors.New("add route fail," + err.Error())
	}

	//routes = []string{"8.8.8.8/32"}

	for _, route := range routes {
		plog.Info("add route ", route, " via ", gateway)
		nm.delRoute(route)
		err = nm.addRoute(route, gateway)
		if err != nil {
			return errors.New("add route fail," + err.Error())
		}
	}
	return nil
}

func (nm *LinuxNetworkManager) RefreshDefaultGateway() error {

	var err error
	nm.defaultGateway, err = nm.getDefaultGateway()
	if err != nil {
		return err
	}

	nm.delRoute(nm.remoteIp)

	return nm.addRoute(nm.remoteIp, nm.defaultGateway)
}

func (nm *LinuxNetworkManager) RestoreNetwork() {

	plog.Infof("restore network service")
	if nm.remoteIp != "" {
		nm.delRoute(nm.remoteIp)
	}
	nm.restoreDnsServer()
}
