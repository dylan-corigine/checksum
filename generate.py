from scapy.all import send, IP, TCP, Raw, bytes_hex


def calc_header(checksum, packet):
    for i in range(0xffff):
        ver = (i >> 12) 
        ihl = (i >> 8) & 0xf 
        tos = i & 0xff
        packet.version = ver
        packet.ihl = ihl
        packet.tos = tos

        sum = 0
        for j in range(10):
            start = j * 4
            if(j == 5):
                continue
            rep = bytes_hex(packet)[start:start+4]
            rep = "0x" + rep.decode("utf-8")
            sum += int(rep,16)

        add = sum >> 16
        base = sum & 0xffff
        sum = base + add
        chksum = (~sum) & 0xffff
        if (chksum == checksum):
            print("ver = ", hex(ver))
            print("ihl = ", hex(ihl))
            if(checksum == 0xffff):
                tos -=1
            print("tos = ", hex(tos))
            break

pkt = IP()
calc_header(0xffff, pkt)







