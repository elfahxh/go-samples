package pkgwireguard

import (
	"log"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
	wg "golang.zx2c4.com/wireguard/wgctrl"
)

var (
	logger = log.New(os.Stdout, "<pkgwireguard>", log.Lshortfile|log.Ldate|log.Ltime)
)

func TestWireguard() {
	wg0, _ := netlink.LinkByName("wg0")

	if wg0 != nil {
		logger.Println("delete link....")
		netlink.LinkDel(wg0)
	}

	la := netlink.NewLinkAttrs()
	la.Name = "wg0"
	mywireguard := &netlink.Wireguard{LinkAttrs: la}
	logger.Println("add link....")
	err := netlink.LinkAdd(mywireguard)
	if err != nil {
		logger.Printf("could not add %s: %v\n", la.Name, err)
	}
	cmd := exec.Command("bash", "-c", "ip link show type wireguard")
	out, _ := cmd.CombinedOutput()
	logger.Printf("ip link show type wireguard:\n%s\n", string(out))
	// err = netlink.LinkDel(mywireguard)
	// if err != nil {
	// 	fmt.Printf("could not del %s: %v\n", la.Name, err)
	// }
	// cmd = exec.Command("bash", "-c", "ip link show type wireguard")
	// out, _ = cmd.CombinedOutput()
	// fmt.Printf("ip link show type wireguard:\n%s\n", string(out))
	wg0, _ = netlink.LinkByName("wg0")
	addr, _ := netlink.ParseAddr("10.0.0.1/24")
	netlink.AddrAdd(wg0, addr)
	netlink.LinkSetUp(wg0)
	cmd = exec.Command("bash", "-c", "ifconfig wg0")
	out, _ = cmd.CombinedOutput()
	logger.Printf("ifconfig wg0:\n%s\n", string(out))

	wgc, err := wg.New()

	wgd, err := wgc.Device("wg0")

	logger.Printf("Device name = [%s] [%s], [%d], [PrivateKey:%s], [%v]", wgd.Name, wgd.Type, wgd.ListenPort, string(wgd.PrivateKey[:]), wgd)
}
