dns-tunnler
=========

A dns proxy/tunnel for ssh over dns


Install
-------

```bash
git clone https://github.com/callesg/dns-tunnler.git
cd dns-tunnler
npm install native-dns stdio
```

Usage
-----

Setup a dns NS record (ex proxy.example.com) directed to your server (ex 123.123.123.123) 
and on the server run
```bash
nodejs dnsProxyServer.js -d proxy.example.com -p 53 -v
```
I personaly recomend runing it on another port than 53 and redirecting with some
iptables rules so that you dont have to run stuff as root.

When you want to connect to your server you run:

```bash
ssh -C -o ProxyCommand="nodejs dnsProxyClient.js -p 53 -r 8.8.8.8 -d proxy.example.com -s s -t 700" user@example.com
```

Replace proxy.example.com with your own dns name and you can replace 8.8.8.8 with any dns server you can reach.
