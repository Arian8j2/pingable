# Pingable
A simple program for responding to ICMP echo requests when the sequence number is below 100.  
This is useful when the kernel’s automatic echo replies are disabled via `/proc/sys/net/ipv4/icmp_echo_ignore_all`, for example when using ICMP tunnels such as [forwarder](https://github.com/arian8j2/forwarder)  
In Forwarder, the sequence field usually specifies a port and is therefore commonly a large number (greater than 100). By only responding to ICMP echo requests with low sequence numbers, we can detect real ping packets.
