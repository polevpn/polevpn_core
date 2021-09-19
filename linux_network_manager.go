package core

import (
	"errors"
	"os/exec"
)

type LinuxNetworkManager struct {
	sysdns     string
	netservice string
}

func NewLinuxNetworkManager() *LinuxNetworkManager {
	return &LinuxNetworkManager{}
}

func (nm *LinuxNetworkManager) setIPAddressAndEnable(tundev string, ip1 string) error {

	var out []byte
	var err error

	out, err = exec.Command("bash", "-c", "ip addr add dev "+tundev+" local "+ip1+" peer "+ip1).Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}

	out, err = exec.Command("bash", "-c", "ip link set "+tundev+" up").Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *LinuxNetworkManager) setDnsServer(ip string, service string) error {

	return nil
}

func (nm *LinuxNetworkManager) removeDnsServer(service string) error {

	return nil
}

func (nm *LinuxNetworkManager) getNetServiceeDns() (string, string, error) {

	return "", "", errors.New("no net service have ip and dns")
}

func (nm *LinuxNetworkManager) addRoute(cidr string, gw string) error {
	out, err := exec.Command("bash", "-c", "ip route add "+cidr+" via "+gw).Output()
	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err
}

func (nm *LinuxNetworkManager) delRoute(cidr string) error {

	out, err := exec.Command("bash", "-c", "ip route del "+cidr).Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *LinuxNetworkManager) SetNetwork(device string, ip1 string, dns string) error {

	var err error

	plog.Infof("set tun device ip as %v", ip1)
	err = nm.setIPAddressAndEnable(device, ip1)
	if err != nil {
		return errors.New("set address fail," + err.Error())
	}

	// nm.netservice, nm.sysdns, err = nm.getNetServiceeDns()

	// plog.Infof("system network service:%v,dns:%v", nm.netservice, nm.sysdns)

	// if err != nil {
	// 	return errors.New("get system dns server fail," + err.Error())
	// }

	// plog.Infof("change network service %v dns to %v", nm.netservice, dns)
	// err = nm.setDnsServer(dns, nm.netservice)

	// if err != nil {
	// 	return errors.New("set dns server fail," + err.Error())
	// }

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

func (nm *LinuxNetworkManager) RestoreNetwork() {

	plog.Infof("restore network service %v", nm.netservice)
	nm.removeDnsServer(nm.netservice)
	if nm.sysdns != "" {
		plog.Infof("set service %v dns to %v", nm.netservice, nm.sysdns)
		nm.setDnsServer(nm.sysdns, nm.netservice)
	}
}
