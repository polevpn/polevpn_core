package core

type NetworkManager interface {
	SetNetwork(device string, ip string, dns string) error
	RestoreNetwork()
}
