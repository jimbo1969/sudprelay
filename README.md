# sudprelay
simple UDP relay (sUDPrelay)

This is a fork of sudppipe (https://aluigi.altervista.org/mytoolz.htm#sudppipe) (simple UDP proxy/pipe, by Luigi Auriemma).  
The original is super-cool, but lacks the ability to send/receive multicast, which I needed.  So I forked Luigi's product and added multicast.
I renamed this version to sudprelay to distinguish it from sudppipe.  Lastly, I had to include a few Windows-related headers and functions that
evidently were handled automagically by MinGW (Luigi's sudppipe compiling environment) that were missing when compiling with Visual Studio 2019.

It runs on Windows or Linux.

Install on Linux:
1) Install CMake
2) Clone or download the zip for this repo git clone https://github.com/jimbo1969/sudprelay.git
3) $ cd sudprelay
4) $ cmake .
5) $ make
6) $ sudo make install

Install on Windows:
1) Install CMake
2) Clone or download the zip for this repo git clone https://github.com/jimbo1969/sudprelay.git
3) >cmake-gui
4) Choose source folder & build folders
5) Configure, Generate, Open Project --> Project opens in Visual Studio
6) Compile in Visual Studio

Execute sudprelay.exe at the command line for usage instructions.
See the original sudppipe (https://aluigi.altervista.org/mytoolz.htm#sudppipe) for more details,
    a description of command line arguments, and usage.  (I found some of the terminology to be
    a bit ambiguous or confusing, so to clarify:  Luigi's 'server' is the target(s) for outbound
    relayed packets, and his 'client(s)' is/are the publishers of packets inbound to the relay.
    He has some additional (chat-related) capabilities that blur the lines, and make my choices
    of terminology ('listen'/'inbound' and 'target'/'send'/'outbound') also imperfect.)
This version will do multicast, using two new options:
-m specifies a multicast address to join via the listening interface (specified by -b)
-T specifies a TTL to use for outgoing multicast packets (sent via interface specified by -B)

Example Relay Use:
$ sudprelay.exe -b [LOCAL_LISTEN_IP] -m [MULTICAST_GRP_LISTEN] -B [LOCAL_SENDING_IP] -T [MULTICAST_TTL] [TARGET_IP] [TARGET_PORT] [LISTEN_PORT]
where:
[LOCAL_LISTEN_IP] = the IPv4 address (e.g. 192.168.0.15) of the interface to use to listen for UDP
[MULTICAST_GRP_LISTEN] = the IPv4 multicast group (e.g. 235.0.0.5) to join on the listening interface
[LOCAL_SENDING_IP] = the IPv4 address (e.g. 192.168.0.5) of the interface to use to send the outbound UDP
[MULTICAST_TTL] = the TTL (e.g. 32 for subnet-bound multicast) for outbound multicast
[TARGET_IP] = the target IPv4 address for unicast (e.g. 192.168.0.10) or multicast (237.0.0.10)
    (you can specify more than one target in a comma-delimited list including port numbers (e.g. 192.168.0.10:5555,237.0.0.10:4444))
[TARGET_PORT] = the default port number (e.g. 5555) to send outbound UDP to on the target if not specified in [TARGET_IP]
[LISTEN_PORT] = the port (e.g. 5444) on the listening interface to which to listen for unicast or multicast UDP

$ sudprelay -b 192.168.0.15 -m 235.0.0.15 -B 192.168.0.5 -T 32 237.0.0.10 5555 5444

The above command binds to the interface hosting IPv4 address 192.168.0.15 for both inbound (on port 5444) and outbound (on port 5555) UDP.  It joins multicast group 235.0.0.5 for listening, and republishes (with TTL=32) whatever it receives there to another multicast group - 237.0.0.10 - on port 5555
