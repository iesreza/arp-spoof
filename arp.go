package arp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

var defaultSerializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

type Arp struct {
	IP net.IP
	HardwareAddress net.HardwareAddr
}


func (c *Arp)WhoHas(ip net.IP) []byte {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       c.HardwareAddress,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, //Broadcast
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(c.HardwareAddress),
		SourceProtAddress: []byte(c.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0}, //Broadcast
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	arp.DstProtAddress = []byte(ip)
	gopacket.SerializeLayers(buf, defaultSerializeOpts, &eth, &arp)


	return buf.Bytes()
}

/*// buildPacket creates an template ARP packet with the given source and
// destination.
func IsAt(src *Address, dst *Address) (layers.Ethernet, layers.ARP, error) {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,

		SrcMAC: src.HardwareAddr,
		DstMAC: dst.HardwareAddr,
	}
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,

		HwAddressSize:   6,
		ProtAddressSize: 4,

		SourceHwAddress:   []byte(src.HardwareAddr),
		SourceProtAddress: []byte(src.IP.To4()),

		DstHwAddress:   []byte(dst.HardwareAddr),
		DstProtAddress: []byte(dst.IP.To4()),
	}
	return ether, arp, nil
}*/