# ARP Spoofing

Our modern day internet is upon a wide range of protocols, but two of the most foundational layers are Ethernet and IP. Before I go into ARP spoofing, it's important to understand why ARP exists.


## Ethernet

Ethernet is the language at the foundation of most networks in the world. An ethernet network, also referred to as a "broadcast domain" functions on the concept of "mac addresses." These addresses are the ones that you see in the form of `AB:CD:EF:12:34:56` (not to be confused with IPv6, which looks something like `ABCD:EFGH::1`). Ethernet also works primarily on the concept of broadcasts, as there isn't much supporting routing infrastructure (though ethernet *switches* *do* have some ethernet routing capabilities employed by analyzing normal traffic). Once a switch can deduce which port has a certain host on it though, the packets stop getting broadcast on every port, and are instead directed to the port the destination mac address is suspected to be on.


## IP

IP is the routable layer of the networking stack. It's based on the concept of "subnetting," where certain sets of IP addresses are grouped together, and packets are routed across separate ethernet networks to make it to their final destination.

For example, let's say you have a network, `A`, with an IP subnet of `10.0.0.0/24`, and another network, `B`, with an IP subnet of `10.1.0.0/24`. These networks are isolated from one another. Hosts on network `A` cannot talk to hosts on network `B`, and vice versa. However, there is a device that sits on both networks, which has the IP addresses `10.0.0.1` and `10.1.0.1`. This device can also forward packets from network `A` onto network `B`, and vice versa. This is called a router. Its job is to maintain a list of where to go for each set of IP addresses you might be attempting to access. If it can't get the packet there, it knows who does.


## The "glue"

Network cards and switches speak ethernet, not IP (usually). The IP traffic is passed as the body/data/payload within the ethernet packets. In software engineering, this is called a "wrapper". The network switches don't speak IP, but you need to get IP traffic through them, so you "wrap" your IP packets in ethernet packets.

Now the big question: If ethernet has a different type of address than IP, why don't I have to use the device's ethernet address to send data to it?

The solution? ARP.


### So what is ARP?

ARP is short for Address Resolution Protocol. It is a protocol that allows computers to request an ethernet/mac address for a computer using an IP address. The process is as follows:

1. I want to go to 10.0.0.1, but I don't know its mac address
2. I craft and send an ARP packet using the broadcast address (`FF:FF:FF:FF:FF:FF`) as the destination.
  * This packet contains my IP address, my mac address, and the IP address I'm looking for.
  * This packet is sent as a broadcast to the whole network, so everyone sees it.
3. The device who owns that address now crafts and sends a response.
  * This response is addressed directly to me, using the mac address from my query.
  * This response contains the IP address I asked for, the mac address of the owner, my IP, and my mac address.
4. I optionally save this response for future reference.
5. I create an IP packet like normal, then wrap it in an ethernet frame using the mac address I just received, and send it.


### Routing

What if I want to send a packet outside my network? I can't get a broadcast there to use ARP, so something else needs to be going on.

\[Enter Routers\]

I already explained what routers do in a previous section, but how do we get them to do what they do (forward packets)?

Well, basically all we need to do is get our IP traffic to them. If they see the traffic, they'll pass it on. To do this, we must go one layer below IP. If in the ethernet packet, we address it to the router, but in the IP packet, we address it to a host on the other network, then our ethernet switches will get the data to the router, where it gets unwrapped, and the IP data is analyzed. If the router knows where the destination is (or who else can get it there), it wraps the IP packet back up in a *new* ethernet frame, and sends it out the other ethernet port.


## Back to ARP spoofing

What if we want to receive the traffic intended for another device on the same network? Well, what if we could convince someone else on the network that we are that device? This is what ARP spoofing does. While ARP may be a request/response model, many devices hoard these packets in a cache, like when you secretly overhear and attempt to memorize the names of other people at a social gathering. Using this knowledge, we can tell other devices that we own our target IP address, before they even ask. They will store away this information in their cache so they don't *have* to ask, and happily send packets our way.

Sometimes they do ask though... No problem! Just spam them continuously with assertions that we are who they're looking for, and most of the packets will go to us.


### Routing... Pt. 2

What if we want to see their *internet* traffic? Well, we need to get them to address their ethernet packets to us. Luckily, routers (aka default gateways) are referenced by IP address, which means clients use ARP to look up their mac address for the ethernet packets. If we just continuously spam them with ARP replies indicating that we own the IP of the router, they'll address their internet traffic to us instead!


### Crap. What do I do with this data?

Well, usually the first few packets of a connection aren't all that useful. We want them to *keep* sending packets. They'll only do that if they think someone's on the other end, so we need to convince them someone is. One method of doing this is by forwarding these packets to the *actual* router, but then we only hear one end of the connection. What if we want both? ARP spoof again! This time, in the opposite direction. When the server on the other end of the connection sends data back, our router is going to look up the mac address of our target using ARP, so we just need to make sure it doesn't have to. SPAM IT! We can spam the router with ARP replies indicating that we are our target, and it will happily send us the responses, too. Now all we need to do is forward them through to the target, and we've successfully executed a man-in-the-middle (MITM) attack! Well... more like man-off-to-the-side-who-can-hear-everything, because we're not really in the middle, but we've convinced them to talk through us anyway.
