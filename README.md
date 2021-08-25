# sudprelay
simple UDP relay (sUDPrelay)

This is a fork of sudppipe (https://aluigi.altervista.org/mytoolz.htm#sudppipe) (simple UDP proxy/pipe), by Luigi Auriemma.  
The original was super-cool, but lacked the ability to send/receive multicast, which I needed.  So I forked it and added it.
It runs on Windows or Linux.

Install on Linux:
1) Install CMake
2) Clone or download the zip for this repo git clone https://github.com/jimbo1969/sudprelay.git
3) cd sudprelay
4) cmake .
5) make
6) make install

Install on Windows:
1) Install CMake
2) Clone or download the zip for this repo git clone https://github.com/jimbo1969/sudprelay.git
3) cmake-gui
4) Choose source folder & build folders
5) Configure, Generate, Open Project --> Project opens in Visual Studio
6) Compile in Visual Studio

Execute sudprelay.exe at the command line for usage instructions.
See the original sudppipe (https://aluigi.altervista.org/mytoolz.htm#sudppipe) for more details.
This version will do multicast, using two new options:
-m specifies a multicast address to join via the listening interface (specified by -b)
-T specifies a TTL to use for outgoing multicast packets (sent via interface specified by -B)

Example Relay Use:
sudprelay.exe -b [LOCAL_LISTEN_IP] -B [LOCAL_SENDING_IP] -m [MULTICAST_GRP_LISTEN] -T [MULTICAST_TTL] [TARGET_IP] [TARGET_PORT] [LISTEN_PORT]
where:
[LOCAL_LISTEN_IP] = the IPv4 address (e.g. 192.168.0.5) of the interface to use to listen for UDP
[LOCAL_SENDING_IP] = the IPv4 address (e.g. 192.168.0.5) of the interface to use to send the outbound UDP
[MULTICAST_GRP_LISTEN] = the IPv4 multicast group (e.g. 235.0.0.5) to join on the listening interface
[MULTICAST_TTL] = the TTL (e.g. 32 for subnet-bound multicast) for outbound multicast
[TARGET_IP] = the target IPv4 address for unicast (e.g. 192.168.0.10) or multicast (237.0.0.10)
    (you can specify more than one target in a comma-delimited list including port numbers (e.g. 192.168.0.10:5555,237.0.0.10:4444))
[TARGET_PORT] = the default port number (e.g. 5555) to send outbound UDP to on the target if not specified in [TARGET_IP]
[LISTEN_PORT] = the port on the listening interface to which to listen for unicast or multicast UDP

