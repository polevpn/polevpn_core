package core

type NetworkManager interface {
	SetNetwork(device string, gateway string, remoteIp string, dns string, routes []string) error
	RestoreNetwork()
	RefreshDefaultGateway() error
}
