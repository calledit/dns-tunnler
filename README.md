dns-tunnler
=========

A dns proxy/tunnel for ssh over dns


Install
-------

```bash
git clone https://github.com/calledit/dns-tunnler.git
cd dns-tunnler
npm install native-dns@0.4.1 stdio request
```

Usage
-----

Setup a dns NS record (ex proxy.example.com) directed to your server (ex 123.123.123.123) 
and on the server run
```bash
nodejs dnsProxyServer.js -d proxy.example.com -p 53 -v
```
I recomend runing it on another port than 53 and redirecting with some
iptables rules so that you dont run the program as root.

example
```iptables
# External accept udp for external dns
-A INPUT -i $EXTIF -m conntrack --ctstate NEW,ESTABLISHED,RELATED -p udp -s $UNIVERSE -d $EXTIP --dport 5453 -j ACCEPT
#External dns redirect from port 53 to 5453
-A PREROUTING -p udp -d $EXTIP --dport 53 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j REDIRECT --to-port 5453
```

To connect with ssh you can run:

```bash
ssh -C -o ProxyCommand="node dnsProxyClient.js -d proxy.example.com" user@example.com
```
Log data throgh dns from a client:
```bash
nslookup ${logdata}.logpwd.proxy.example.com




Replace proxy.example.com with your own dns name. There are a few timing baed parameters that effect speed and latency reducing -t from the default 500 ms lowers the latency at the expense of more frequent requests.
