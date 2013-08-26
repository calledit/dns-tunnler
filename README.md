dns-proxy
=========

A dns proxy/tunnel for ssh over dns


Install:

npm install native-dns stdio


Usage:

Direct your NS record towards you proxy server
and run

nodejs dnsProxyServer.js -d proxy.example.com -p 53 -v

I personaly recomend runing it on another port than 53 and redirecting with some
iptables rules so that you dont have to run stuff as root.

To connect to the proxy server from your client:

ssh -D 1234 -C -o ProxyCommand="nodejs dnsProxyClient.js -p 53 -r ${Some_Dns_Server_That_You_Can_Reach} -d proxy.example.com -s s -t 700" user@example.com


Insperation from ozymandns (This is not compatible with the ozymandns tunnel)
ozymandns took way to much cpu power on my laptop that was my main reason for building this.
