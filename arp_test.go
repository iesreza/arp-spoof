package arp_test

import (
	"github.com/google/gopacket/pcap"
	"github.com/iesreza/arp-spoof"
	"github.com/iesreza/gutil/log"
	"github.com/iesreza/netconfig"
	"net"
	"testing"
)

func TestWhoIs(t *testing.T) {


	config := netconfig.GetNetworkConfig()
	var ip = net.ParseIP("192.168.10.30")
	var obj = arp.Arp{
		IP:config.LocalIP,
		HardwareAddress: config.HardwareAddress,
	}
	var bytes = obj.WhoHas(ip)

	handler, err := pcap.OpenLive(config.InterfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()
	for i:=0; i < 10; i++{
		err = handler.WritePacketData(bytes)
		if err != nil{
			log.Fatal(err)
		}
	}


}
