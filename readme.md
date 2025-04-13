# Rawsock Toolbox

This project contains a variety of tools utilizing raw sockets for things like logging, spoofing, and routing. There's not much to it yet, but I have a growing interest in low-level networking and want to exercise my knowledge on the topic, hopefully learning more along the way.


## Utilities

* `arp` - Address Resolution Protocol
  * `passive-log`
    * Logs ARP packets found on the given interface in plain english.
  * `spoof` (TODO)
    * Sends gratuitous ARP packets for use in an "arp spoofing" attack
  * `spoof-proxy` (TODO)
    * Performs a bidirectional arp-spoofing attack, but proxies packets back to the original router and vice versa.
