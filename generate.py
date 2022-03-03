from scapy.all import send, IP, TCP, Raw, bytes_hex


# Given a desired checksum, calculate the corresponding
# IP header values for: packet.version, packet.ihl and 
# packet.tos.

def calc_header(checksum, packet):
    # The first consideration when building this function
    # is how many bytes we need to modify to arrive at
    # our desired checksum. For an IP packet, we need 
    # to modify 2 bytes worth of data. This is because
    # the first step in calculating the checksum involves
    # the addition of header words (2 byte fields).
    # For more information see: https://en.wikipedia.org/wiki/IPv4_header_checksum
    
    # In order to modify 2 bytes of data in the packet
    # we need to choose 2 bytes worth of IP header fields
    # that we can change dynamically. The fields should be
    # consecutive.
    
    # For a reference on IP header fields have a look at:
    # https://upload.wikimedia.org/wikipedia/commons/thumb/6/60/IPv4_Packet-en.svg/1200px-IPv4_Packet-en.svg.png
    
    # We see that the first 3 header fields (version, ihl and tos)
    # make up 2 bytes worth of data. The goal is to loop from
    # 0x0000 (2 bytes) to 0xffff(2 bytes) and then assign these header
    # fields the corresponding values.
    
    # For example if i= 0x00ff we would have version=0, 
    # ihl = 0 and tos = 0xff
    
    for i in range(0xffff):
        # 2 bytes = 16 bits
        # packet.version has a end position after 4 bits so we need to
        # shift i by 16-4=12 bits
        ver = (i >> 12) 
        # ihl has a end position after 8 bits so we need to shift i by
        # 16-8=8 bits
        # However after shifting by 8 bits we still have the contents
        # of packet.version so we AND with 0xf (4 bits) which effectively
        # removes packet.version which we don't want
        ihl = (i >> 8) & 0xf 
        # Tos is simply the last byte of i, so we simply and with 0xff( 8 bits)
        tos = i & 0xff
        
        # Set packet header fields to calculated value
        packet.version = ver
        packet.ihl = ihl
        packet.tos = tos
        
        # We now calculate the checksum after assigning our
        # precomputed header fields and determine if it matches
        # our desired checksum.
        # To start, sum each word in the IP packet. There are
        # 10 words in an IP packet.
        sum = 0
        for j in range(10):
            start = j * 4
            # skip the checksum field ( 2 bytes)
            # which is not added to the total sum.
            if(j == 5):
                continue
            # obtain hex string representation of IP packet,
            # extract 4 characters at a time from hex string
            # which equals 2 bytes.
            rep = bytes_hex(packet)[start:start+4]
            
            rep = "0x" + rep.decode("utf-8")
            # Convert rep into integer and add to sum
            sum += int(rep,16)

        # Result at this stage is 20 bits. We need to seperate the carry
        # digits which is the last 4 bits of the result, sum. We therefore
        # need to shift sum by 20-4=16 bits. This result is then added to 
        # base. This is just how the checksum calculation is defined for IP
        # packets.
        add = sum >> 16
        # Base contains the 2 byte result, to which we add the carry digits.
        base = sum & 0xffff
        # Add the carry digits
        sum = base + add
        # The checksum is then defined as the one's complement of sum.
        # We also ensure we only capture 2 bytes of the checksum
        # by ANDing with 0xffff (2 bytes)
        chksum = (~sum) & 0xffff
        if (chksum == checksum):
            print("ver = ", hex(ver))
            print("ihl = ", hex(ihl))
            # Fix off by one error
            if(checksum == 0xffff):
                tos -=1
            print("tos = ", hex(tos))
            break

pkt = IP()
calc_header(0xffff, pkt)







