# Awesome Honeypots  

[![Awesome Honeypots](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome honeypots, tools, components and much more. The list is divided into categories such as web, services, and others, focusing on open source projects.

There is no pre-established order of items in each category, the order is for contribution. If you want to contribute, please read the [guide](CONTRIBUTING.md).

Discover more awesome lists at [sindresorhus/awesome](https://github.com/sindresorhus/awesome).

### Sections

- [Honeypots](#honeypots)
- [Honeyd Tools](#honeyd)
- [Network and Artifact Analysis](#analysis)
- [Data Tools](#visualizers)
- [Guides](#guides)

## Related Lists
- [awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools), useful in network traffic analysis.
- [awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis), with some overlap here for artifact analysis.

## <a name="honeypots"></a> Honeypots

- Database Honeypots
    - [Delilah](https://github.com/Novetta/delilah) - An Elasticsearch Honeypot written in Python.
    - [ESPot](https://github.com/mycert/ESPot) - An Elasticsearch honeypot written in NodeJS, to capture every attempts to exploit CVE-2014-3120.
    - [Elastic honey](https://github.com/jordan-wright/elastichoney) - A Simple Elasticsearch Honeypot.
    - [HoneyMysql](https://github.com/xiaoxiaoleo/HoneyMysql) - A simple Mysql honeypot project.
    - [MongoDB-HoneyProxy](https://github.com/Plazmaz/MongoDB-HoneyProxy) - A MongoDB honeypot proxy.
    - [NoSQLpot](https://github.com/torque59/nosqlpot) - The NoSQL Honeypot Framework.
    - [mysql-honeypotd](https://github.com/sjinks/mysql-honeypotd) - Low interaction MySQL honeypot written in C.
    - [MysqlPot](https://github.com/schmalle/MysqlPot) - A mysql honeypot, still very very early stage.
    - [pghoney](https://github.com/betheroot/pghoney) - Low-interaction Postgres Honeypot.
    - [sticky_elephant](https://github.com/betheroot/sticky_elephant) - medium interaction postgresql honeypot.

- Web honeypots
    - [Bukkit Honeypot](https://github.com/Argomirr/Honeypot) Honeypot - A honeypot plugin for Bukkit.
    - [EoHoneypotBundle](https://github.com/eymengunay/EoHoneypotBundle) - Honeypot type for Symfony2 forms.
    - [Glastopf](https://github.com/mushorg/glastopf) - Web Application Honeypot.
    - [Google Hack Honeypot](http://ghh.sourceforge.net) - designed to provide reconnaissance against attackers that use search engines as a hacking tool against your resources.
    - [Laravel Application Honeypot](https://github.com/msurguy/Honeypot) - Honeypot - Simple spam prevention package for Laravel applications.
    - [Nodepot](https://github.com/schmalle/Nodepot)  - A nodejs web application honeypot.
    - [Servletpot](https://github.com/schmalle/servletpot) - Web application Honeypot.
    - [Shadow Daemon](https://shadowd.zecure.org/overview/introduction/) - A modular Web Application Firewall / High-Interaction Honeypot for PHP, Perl & Python apps.
    - [WebTrap](https://github.com/IllusiveNetworks-Labs/WebTrap) - Designed to create deceptive webpages to deceive and redirect attackers away from real websites.
    - [basic-auth-pot](https://github.com/bjeborn/basic-auth-pot) bap - http Basic Authentication honeyPot.
    - [django-admin-honeypot](https://github.com/dmpayton/django-admin-honeypot) - A fake Django admin login screen to notify admins of attempted unauthorized access. 
    - [honeyhttpd](https://github.com/bocajspear1/honeyhttpd) - a Python-based web server honeypot builder.
    - [phpmyadmin_honeypot](https://github.com/gfoss/phpmyadmin_honeypot) - - A simple and effective phpMyAdmin honeypot.
    - [shockpot](https://github.com/threatstream/shockpot) - WebApp Honeypot for detecting Shell Shock exploit attempts.
    - [smart-honeypot](https://github.com/freak3dot/smart-honeypot) - PHP Script demonstrating a smart honey pot.
    - Snare/Tanner - successors to Glastopf
      - [Snare](https://github.com/mushorg/snare) - Super Next generation Advanced Reactive honEypot
      - [Tanner](https://github.com/mushorg/tanner) - Evaluating SNARE events
    - [stack-honeypot](https://github.com/CHH/stack-honeypot) - Inserts a trap for spam bots into responses.
    - WordPress honeypots
        - [HonnyPotter](https://github.com/MartinIngesen/HonnyPotter) - A WordPress login honeypot for collection and analysis of failed login attempts.
        - [HoneyPress](https://github.com/dustyfresh/HoneyPress) - python based WordPress honeypot in a docker container.
        - [wp-smart-honeypot](https://github.com/freak3dot/wp-smart-honeypot) - WordPress plugin to reduce comment spam with a smarter honeypot.
        - [wordpot](https://github.com/gbrindisi/wordpot) - A WordPress Honeypot.

- Service Honeypots
    - [AMTHoneypot](https://github.com/packetflare/amthoneypot) - Honeypot for Intel's AMT Firmware Vulnerability CVE-2017-5689.
    - [Ensnare](https://github.com/ahoernecke/ensnare) - Easy to deploy Ruby honeypot.
    - [HoneyPy](https://github.com/foospidy/HoneyPy) - A low interaction honeypot.
    - [Honeygrove](https://github.com/UHH-ISS/honeygrove) - A multi-purpose modular honeypot based on Twisted.
    - [Honeyport](https://github.com/securitygeneration/Honeyport) - A simple honeyport written in Bash and Python.
    - [Honeyprint](https://github.com/glaslos/honeyprint) - Printer honeypot.
    - [Lyrebird](https://hub.docker.com/r/lyrebird/honeypot-base/) - A modern high-interaction honeypot framework.
    - [MICROS honeypot](https://github.com/Cymmetria/micros_honeypot) -  low interaction honeypot to detect CVE-2018-2636 in the Oracle Hospitality Simphony component of Oracle Hospitality Applications (MICROS).
    - [RDPy](https://github.com/citronneur/rdpy) - A Microsoft Remote Desktop Protocol (RDP) honeypot in python.
    - [SMB Honeypot](https://github.com/r0hi7/HoneySMB) -  High interaction SMB service Honeypot capable of capturing wannacry like Malware.
    - [Tom's Honeypot](https://github.com/inguardians/toms_honeypot) - Low interaction Python honeypot.
    - [WebLogic honeypot](https://github.com/Cymmetria/weblogic_honeypot) - low interaction honeypot to detect CVE-2017-10271 in the Oracle WebLogic Server component of Oracle Fusion Middleware.
    - [WhiteFace Honeypot](https://github.com/csirtgadgets/csirtg-honeypot) - Twisted based HoneyPot for WhiteFace whiteface.csirtgadgets.com
    - [honeycomb_plugins](https://github.com/Cymmetria/honeycomb_plugins) - The plugin repository for Honeycomb, the honeypot framework by Cymmetria.
    - [honeyntp](https://github.com/fygrave/honeyntp) - NTP logger/honeypot.
    - [honeypot-camera](https://github.com/alexbredo/honeypot-camera) - observation camera honeypot.
    - [honeytrap](https://github.com/honeytrap/honeytrap) - Advanced Honeypot framework written in Go. Can be connected up with other Honeypot software.
    - [troje](https://github.com/dutchcoders/troje/) - a honeypot built around lxc containers. It will run each connection with the service within a seperate lxc container.

- Distributed Honeypots
    - [DemonHunter](https://github.com/RevengeComing/DemonHunter) - Low interaction Honepot Server.

- Anti-honeypot stuff
    - [kippo_detect](https://github.com/andrew-morris/kippo_detect) - This is not a honeypot, but it detects kippo. (This guy has lots of more interesting stuff)

- ICS/SCADA honeypots
    - [Conpot](https://github.com/mushorg/conpot) - ICS/SCADA honeypot.
    - [GasPot](https://github.com/sjhilt/GasPot) - Veeder Root Gaurdian AST, common in the oil and gas industry.
    - [SCADA honeynet](http://scadahoneynet.sourceforge.net) - Building Honeypots for Industrial Networks.
    - [gridpot](https://github.com/sk4ld/gridpot) - Open source tools for realistic-behaving electric grid honeynets .
    - [scada-honeynet](http://www.digitalbond.com/blog/2007/07/24/scada-honeynet-article-in-infragard-publication/) - mimics many of the services from a popular PLC and better helps SCADA researchers understand potential risks of exposed control system devices.

- Other/random
    - [DSHP](https://github.com/naorlivne/dshp) - Damn Simple HoneyPot with pluggable handlers.
    - [NOVA](https://github.com/DataSoft/Nova) uses honeypots as detectors, looks like a complete system.
    - [OFPot](https://github.com/upa/ofpot) - OpenFlow Honeypot, redirects traffic for unused IPs to a honeypot. Built on POX.
    - [Open Canary](https://pypi.org/project/opencanary/) - A low interaction honeypot intended to be run on internal networks.
    - [OpenCanary](https://github.com/thinkst/opencanary) - Modular and decentralised honeypot.

- Botnet C2 tools
    - [Hale](https://github.com/pjlantz/Hale) - Botnet command &amp; control monitor.
    - [dnsMole](https://code.google.com/archive/p/dns-mole/) -  analyse dns traffic, and to potentionaly detect botnet C&C server and infected hosts.

- IPv6 attack detection tool
    - [ipv6-attack-detector](https://github.com/mzweilin/ipv6-attack-detector/)  - Google Summer of Code 2012 project, supported by The Honeynet Project organization.

- Dynamic code instrumentation toolkit
    - [Frida](https://www.frida.re) - Inject JavaScript to explore native apps on Windows, Mac, Linux, iOS and Android.

- Tool to convert website to server honeypots
    - [HIHAT](http://hihat.sourceforge.net/) - Transform arbitrary PHP applications into web-based high-interaction Honeypots.

- Malware collector
    - [Kippo-Malware](https://bruteforcelab.com/kippo-malware) - Python script that will download all malicious files stored as URLs in a Kippo SSH honeypot database.

- Distributed sensor deployment
    - [ADHD](https://sourceforge.net/projects/adhd/) -  Active Defense Harbinger Distribution (ADHD) is a Linux distro based on Ubuntu LTS. It comes with many tools aimed at active defense preinstalled and configured.
    - [Modern Honey Network](https://github.com/threatstream/mhn) - Multi-snort and honeypot sensor management, uses a network of VMs, small footprint SNORT installations, stealthy dionaeas, and a centralized server for management.
    - [Smarthoneypot](https://smarthoneypot.com/) - custom honeypot intelligence system that is simple to deploy and easy to manage.

- Network Analysis Tool
    - [Tracexploit](https://code.google.com/archive/p/tracexploit/) - replay network packets.

- Log anonymizer
    - [LogAnon](http://code.google.com/archive/p/loganon/) - log anonymization library that helps having anonymous logs consistent between logs and network captures.

- Low interaction honeypot (router back door)
    - [Honeypot-32764](https://github.com/knalli/honeypot-for-tcp-32764) - Honeypot for router backdoor (TCP 32764).

- honeynet farm traffic redirector
    - [Honeymole](https://web.archive.org/web/20100326040550/http://www.honeynet.org.pt:80/index.php/HoneyMole) - eploy multiple sensors that redirect traffic to a centralized collection of honeypots.

- HTTPS Proxy
    - [mitmproxy](https://mitmproxy.org/) - allows traffic flows to be intercepted, inspected, modified and replayed.

- System instrumentation
    - [Sysdig](https://sysdig.com/opensource/) - open source, system-level exploration: capture system state and activity from a running Linux instance, then save, filter and analyze.
    - [Fibratus](https://github.com/rabbitstack/fibratus) - tool for exploration and tracing of the Windows kernel.

- Honeypot for USB-spreading malware
    - [Ghost-usb](https://github.com/honeynet/ghost-usb-honeypot) -  honeypot for malware that propagates via USB storage devices.
    - [Honeystick](http://www.ukhoneynet.org/research/honeystick-howto/)  - low interaction honeypot on USB stick

- Data Collection
    - [Kippo2MySQL](https://bruteforcelab.com/kippo2mysql) -  extracts some very basic stats from Kippo’s text-based log files (a mess to analyze!) and inserts them in a MySQL database.
    - [Kippo2ElasticSearch](https://bruteforcelab.com/kippo2elasticsearch) - Python script to transfer data from a Kippo SSH honeypot MySQL database to an ElasticSearch instance (server or cluster).

- Passive network audit framework parser
    - [pnaf](https://github.com/jusafing/pnaf) - Passive Network Audit Framework.

- VM monitoring and tools
    - [Antivmdetect](https://github.com/nsmfoo/antivmdetection) - Script to create templates to use with VirtualBox to make vm detection harder.
    - [VMCloak](https://github.com/jbremer/vmcloak) - Automated Virtual Machine Generation and Cloaking for Cuckoo Sandbox.
    - [vmitools](http://libvmi.com/) - C library with Python bindings that makes it easy to monitor the low-level details of a running virtual machine.
    - [vmscope](https://cs.gmu.edu/~xwangc/Publications/RAID07-VMscope.pdf) - Monitoring of VM-based.

- Binary debugger
    - [Hexgolems - Pint Debugger Backend](https://github.com/hexgolems/pint) - A debugger backend and LUA wrapper for PIN.
    - [Hexgolems - Schem Debugger Frontend](https://github.com/hexgolems/schem) - A debugger frontend.

- Mobile Analysis Tool
    - [Androguard](https://github.com/androguard/androguard) - Reverse engineering, Malware and goodware analysis of Android applications ... and more.
    - [APKinspector](https://github.com/honeynet/apkinspector/) - APKinspector is a powerful GUI tool for analysts to analyze the Android applications.

- Low interaction honeypot
    - [Honeyperl](https://sourceforge.net/projects/honeyperl/) - Honeypot software based in Perl with plugins developed for many functions like : wingates, telnet, squid, smtp, etc.

- Honeynet data fusion
    - [HFlow2](https://projects.honeynet.org/hflow) -  data coalesing tool for honeynet/network analysis.

- Server
    - [Amun](http://amunhoney.sourceforge.net) - vulnerability emulation honeypot.
    - [Artillery](https://github.com/trustedsec/artillery/) - open-source blue team tool designed to protect Linux and Windows operating systems through multiple methods.
    - [Bait and Switch](http://baitnswitch.sourceforge.net) - redirects all hostile traffic to a honeypot that is partially mirroring your production system.
    - [Bifrozt](https://github.com/Ziemeck/bifrozt-ansible) - Automatic deploy bifrozt with ansible.
    - [Conpot](http://conpot.org/) - ow interactive server side Industrial Control Systems honeypot.
    - [Heralding](https://github.com/johnnykv/heralding) - A credentials catching honeypot.
    - [HoneyWRT](https://github.com/CanadianJeff/honeywrt) - low interaction Python honeypot designed to mimic services or ports that might get targeted by attackers.
    - [Honeyd](https://github.com/provos/honeyd) Also see [more honeyd tools](#honeyd).
    - [Honeysink](http://www.honeynet.org/node/773) - open source network sinkhole that provides a mechanism for detection and prevention of malicious traffic on a given network.
    - [Hontel](https://github.com/stamparm/hontel) - Telnet Honeypot.
    - [KFSensor](http://www.keyfocus.net/kfsensor/) - Windows based honeypot Intrusion Detection System (IDS).
    - [LaBrea](http://labrea.sourceforge.net/labrea-info.html) - takes over unused IP addresses, and creates virtual servers that are attractive to worms, hackers, and other denizens of the Internet.
    - [MTPot](https://github.com/Cymmetria/MTPot) - Open Source Telnet Honeypot, focused on Mirai malware.
    - [SIREN](https://github.com/blaverick62/SIREN) - Semi-Intelligent HoneyPot Network - HoneyNet Intelligent Virtual Environment.
    - [TelnetHoney](https://github.com/balte/TelnetHoney) - A simple telnet honeypot.
    - [UDPot Honeypot](https://github.com/jekil/UDPot) - Simple UDP / DNS honeypot scripts.
    - [YAFH](https://github.com/fnzv/YAFH) - Yet Another Fake Honeypot written in Go
    - [arctic-swallow](https://github.com/ajackal/arctic-swallow) - a low interaction honeypot.
    - [glutton](https://github.com/mushorg/glutton) - All eating honeypot.
    - [go-HoneyPot](https://github.com/Mojachieee/go-HoneyPot) - A honeypot server written in Go
    - [go-emulators](https://github.com/kingtuna/go-emulators) - honeypot go lang emulators
    - [honeymail](https://github.com/sec51/honeymail) - SMTP honeypot written in Golang
    - [honeytrap](https://github.com/tillmannw/honeytrap) - a low-interaction honeypot and network security tool written to catch attacks against TCP and UDP services.
    - [imap-honey](https://github.com/yvesago/imap-honey) - IMAP honeypot written in Golang
    - [mwcollectd](https://www.openhub.net/p/mwcollectd) - a versatile malware collection daemon, uniting the best features of nepenthes and honeytrap.
    - [portlurker](https://github.com/bartnv/portlurker) - Port listener / honeypot in Rust with protocol guessing and safe string display.
    - [slipm-honeypot](https://github.com/rshipp/slipm-honeypot) - A simple low-interaction port monitoring honeypot.
    - [telnetlogger](https://github.com/robertdavidgraham/telnetlogger) - A Telnet honeypot designed to track the Mirai botnet.
    - [vnclowpot](https://github.com/magisterquis/vnclowpot) - A low interaction VNC honeypot.


- IDS signature generation
    - [Honeycomb](http://www.icir.org/christian/honeycomb/) - Automated signature creation using honeypots.

- Lookup service for AS-numbers and prefixes
    - [CC2ASN](http://www.cc2asn.com/) - A simple lookup service for AS-numbers and prefixes belonging to any given country in the world.

- Data Collection / Data Sharing
    - [HPfriends](http://hpfriends.honeycloud.net/#/home) - Honeypot data-sharing platform.
      - [hpfriends - real-time social data-sharing](http://heipei.github.io/sigint-hpfriends/) - Presentation about HPFriends feed system 
    - [HPFeeds](https://github.com/rep/hpfeeds/) - lightweight authenticated publish-subscribe protocol.

- central management tool
    - [PHARM](http://www.nepenthespharm.com/) - Manage , Report, Analyze your distributed Nepenthes instances.

- Network connection analyzer
    - [Impost](http://impost.sourceforge.net/) - a network security auditing tool designed to analyze the forensics behind compromised and/or vulnerable daemons. 

- Honeypot deployment
    - [Modern Honeynet Network](http://threatstream.github.io/mhn/) - makes deploying and managing secure honeypots extremely simple.

- Honeypot extensions to Wireshark
    - [Whireshark Extensions](https://www.honeynet.org/project/WiresharkExtensions) - support applying Snort IDS rules and signatures against pcap files.


- Client
    - [CWSandbox / GFI Sandbox](https://www.gfi.com/products-and-solutions/all-products)
    - [Capture-HPC-Linux](https://redmine.honeynet.org/projects/linux-capture-hpc/wiki)
    - [Capture-HPC-NG](https://github.com/CERT-Polska/HSN-Capture-HPC-NG)
    - [Capture-HPC](https://projects.honeynet.org/capture-hpc) - a high interaction client honeypot (also called honeyclient).
    - [HoneyBOT](http://www.atomicsoftwaresolutions.com/)
    - [HoneyC](https://projects.honeynet.org/honeyc)
    - [HoneySpider Network](https://github.com/CERT-Polska/hsn2-bundle) - a highly-scalable system integrating multiple client honeypots to detect malicious websites.
    - [HoneyWeb](https://code.google.com/archive/p/gsoc-honeyweb/) - Web interface created to manage and share remotly Honeyclients ressources. 
    - [Jsunpack-n](https://github.com/urule99/jsunpack-n)
    - [MonkeySpider](http://monkeyspider.sourceforge.net)
    - [PhoneyC](https://github.com/honeynet/phoneyc) - Python honeyclient (later replaced by Thug)
    - [Pwnypot](https://github.com/shjalayeri/pwnypot) - High Interaction Client Honeypot
    - [Rumal](https://github.com/thugs-rumal/) - Thug's Rumāl: a Thug's dress & weapon.
    - [Shelia](https://www.cs.vu.nl/~herbertb/misc/shelia/) - a client-side honeypot for attack detection
    - [Thug](https://buffer.github.io/thug/) - Python low-interaction honeyclient
    - [Thug Distributed Task Queuing](https://thug-distributed.readthedocs.io/en/latest/index.html)
    - [Trigona](https://www.honeynet.org/project/Trigona)
    - [URLQuery](https://urlquery.net/)
    - [YALIH (Yet Another Low Interaction Honeyclient)](https://github.com/Masood-M/yalih) - a low Interaction Client honeypot designed to detect malicious websites through signature, anomaly and pattern matching techniques

- Honeypot
    - [Deception Toolkit](http://www.all.net/dtk/dtk.html)
    - [IMHoneypot](https://github.com/mushorg/imhoneypot)
    - [Single-honeypot](https://sourceforge.net/projects/single-honeypot/)

- PDF document inspector
    - [peepdf](https://github.com/jesparza/peepdf) - Powerful Python tool to analyze PDF documents 

- Hybrid low/high interaction honeypot
    - [HoneyBrid](http://honeybrid.sourceforge.net)

- SSH Honeypots
    - [Blacknet](https://github.com/morian/blacknet) - Multi-head SSH honeypot system.
    - [Cowrie](https://github.com/micheloosterhof/cowrie) - Cowrie SSH Honeypot (based on kippo)
    - [DShield docker](https://github.com/xme/dshield-docker) - Docker container running cowrie with DShield output enabled.
    - [HonSSH](https://github.com/tnich/honssh) - HonSSH is designed to log all SSH communications between a client and server.
    - [HUDINX](https://github.com/Cryptix720/HUDINX) - tiny interaction SSH honeypot engineered in Python to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.
    - [Kippo](https://github.com/desaster/kippo) - Medium interaction SSH honeypot
    - [Kippo_JunOS](https://github.com/gregcmartin/Kippo_JunOS) - Kippo configured to be a backdoored netscreen.
    - [Kojoney2](https://github.com/madirish/kojoney2) - low interaction SSH honeypot written in Python. Based on Kojoney by Jose Antonio Coret
    - [Kojoney](http://kojoney.sourceforge.net/) - Kojoney is a low level interaction honeypot that emulates an SSH server. The daemon is written in Python using the Twisted Conch libraries.
    - [LongTail Log Analysis @ Marist College](http://longtail.it.marist.edu/honey/) - analyzed SSH honeypot logs
    - [go-sshoney](https://github.com/ashmckenzie/go-sshoney) - SSH Honeypot
    - [go0r](https://github.com/fzerorubigd/go0r) - A simple ssh honeypot in golang
    - [gohoney](https://github.com/PaulMaddox/gohoney) - A SSH honeypot written in Go
    - [hived](https://github.com/sahilm/hived) - a honeypot 
    - [hnypots-agent)](https://github.com/joshrendek/hnypots-agent) - A SSH Server in Go that logs username/password combos
    - [honeypot.go](https://github.com/mdp/honeypot.go) - SSH Honeypot written in Go
    - [honeyssh](https://github.com/ppacher/honeyssh) - A credential dumping SSH honeypot with statistics
    - [hornet](https://github.com/czardoz/hornet) - Medium interaction SSH Honeypot that supports multiple virtual hosts
    - [ssh-auth-logger](https://github.com/JustinAzoff/ssh-auth-logger) - A low/zero interaction ssh authentication logging honeypot
    - [ssh-honeypot](https://github.com/droberson/ssh-honeypot) - Fake sshd that logs ip addresses, usernames, and passwords.
    - [ssh-honeypotd](https://github.com/sjinks/ssh-honeypotd) - A low-interaction SSH honeypot written in C.
    - [sshForShits](https://github.com/traetox/sshForShits) - framework for a high interaction SSH honeypot
    - [sshesame](https://github.com/jaksi/sshesame) - A fake SSH server that lets everyone in and logs their activity.
    - [sshhipot](https://github.com/magisterquis/sshhipot) - High-interaction MitM SSH honeypot
    - [sshlowpot](https://github.com/magisterquis/sshlowpot) - Yet another no-frills low-interaction ssh honeypot in Go.    
    - [sshsyrup](https://github.com/mkishere/sshsyrup) - A simple SSH Honeypot with features to capture terminal activity and upload to asciinema.org

- Distributed sensor project
    - [DShield Web Honeypot Project](https://sites.google.com/site/webhoneypotsite/)

- A pcap analyzer
    - [Honeysnap](https://projects.honeynet.org/honeysnap/)

- Network traffic redirector
    - [Honeywall](https://projects.honeynet.org/honeywall/)

- Honeypot Distribution with mixed content
    - [HoneyDrive](https://bruteforcelab.com/honeydrive)

- Honeypot sensor
    - [Honeeepi] (https://redmine.honeynet.org/projects/honeeepi/wiki) - Honeeepi is a honeypot sensor on Raspberry Pi which based on customized Raspbian OS.

- File carving
    - [TestDisk & PhotoRec](https://www.cgsecurity.org/)

- Sebek
    - [Qebek](https://projects.honeynet.org/sebek/wiki/Qebek) - QEMU based Sebek. As Sebek, it is data capture tool for high interaction honeypot.
    - [Sebek](https://projects.honeynet.org/sebek/) - data capture
    - [xebek](https://code.google.com/archive/p/xebek/) - Sebek on Xen

- Behavioral analysis tool for win32
    - [Capture BAT](https://www.honeynet.org/node/315)

- Live CD
    - [DAVIX](https://www.secviz.org/node/89) - The DAVIX Live CD

- Spamtrap
    - [Mail::SMTP::Honeypot](https://metacpan.org/pod/release/MIKER/Mail-SMTP-Honeypot-0.11/Honeypot.pm) - perl module that appears to provide the functionality of a standard SMTP server
    - [Mailoney](https://github.com/awhitehatter/mailoney) - SMTP honeypot, Open Relay, Cred Harvester written in python.
    - [SendMeSpamIDS.py](https://github.com/johestephan/VerySimpleHoneypot) Simple SMTP fetch all IDS and analyzer
    - [Shiva](https://github.com/shiva-spampot/shiva) - Spam Honeypot with Intelligent Virtual Analyzer
        - [Shiva The Spam Honeypot Tips And Tricks For Getting It Up And Running](https://www.pentestpartners.com/security-blog/shiva-the-spam-honeypot-tips-and-tricks-for-getting-it-up-and-running/)
    - [SpamHAT](https://github.com/miguelraulb/spamhat) - Spam Honeypot Tool
    - [Spamhole](http://www.spamhole.net/)
    - [honeypot](https://github.com/jadb/honeypot) - The Project Honey Pot un-official PHP SDK
    - [spamd](http://man.openbsd.org/cgi-bin/man.cgi?query=spamd%26apropos=0%26sektion=0%26manpath=OpenBSD+Current%26arch=i386%26format=html)

- Commercial honeynet
    - [Cymmetria Mazerunner](https://cymmetria.com/product/mazerunner/) - MazeRunner leads attackers away from real targets and creates a footprint of the attack.

- Server (Bluetooth)
    - [Bluepot](https://github.com/andrewmichaelsmith/bluepot)

- Dynamic analysis of Android apps
    - [Droidbox](https://code.google.com/archive/p/droidbox/)

- Dockerized Low Interaction packaging
    - [Docker honeynet](https://github.com/sreinhardt/Docker-Honeynet) - Several Honeynet tools set up for Docker containers.
    - [Dockerized Thug](https://hub.docker.com/r/honeynet/thug/) - A dockerized [Thug](https://github.com/buffer/thug) to analyze malicious web content.
    - [Dockerpot](https://github.com/mrschyte/dockerpot) - A docker based honeypot.
    - [Manuka](https://github.com/andrewmichaelsmith/manuka) - Docker based honeypot (Dionaea & Kippo).
    - [mhn-core-docker](https://github.com/MattCarothers/mhn-core-docker) - Core elements of the Modern Honey Network implemented in Docker.

- Network analysis
    - [Quechua](https://bitbucket.org/zaccone/quechua)

- SIP Server
    - [Artemnesia VoIP](http://artemisa.sourceforge.net)

- IOT Honeypot
    - [HoneyThing](https://github.com/omererdem/honeything) - TR-069 Honeypot

- Honeytokens
    - [CanaryTokens](https://github.com/thinkst/canarytokens) - 
    - [Honeybits](https://github.com/0x4D31/honeybits) - A simple tool designed to enhance the effectiveness of your traps by spreading breadcrumbs & honeytokens across your production servers and workstations to lure the attacker toward your honeypots.
    - [Honeyλ](https://github.com/0x4D31/honeylambda) - honeyLambda 'serverless trap' is a simple, serverless application designed to create and monitor URL honeytokens, on top of AWS Lambda and Amazon API Gateway.
    - [dcept](https://github.com/secureworks/dcept) - A tool for deploying and detecting use of Active Directory honeytokens.

## <a name="honeyd"></a> Honeyd Tools

- Honeyd plugin
    - [Honeycomb](http://www.honeyd.org/tools.php)

- Honeyd viewer
    - [Honeyview](http://honeyview.sourceforge.net/)

- Honeyd to MySQL connector
    - [Honeyd2MySQL](https://bruteforcelab.com/honeyd2mysql)

- A script to visualize statistics from honeyd
    - [Honeyd-Viz](https://bruteforcelab.com/honeyd-viz)

- Honeyd UI
    - [Honeyd configuration GUI](http://www.citi.umich.edu/u/provos/honeyd/ch01-results/1/) - application used to configure
the honeyd daemon and generate configuration files

- Honeyd stats
    - [Honeydsum.pl](https://github.com/DataSoft/Honeyd/blob/master/scripts/misc/honeydsum-v0.3/honeydsum.pl)



## <a name="analysis"></a> Network and Artifact Analysis

- Sandbox
    - [Argos](http://www.few.vu.nl/argos/) - An emulator for capturing zero-day attacks
    - [COMODO automated sandbox](https://help.comodo.com/topic-72-1-451-4768-.html)
    - [Cuckoo](https://cuckoosandbox.org/) - he leading open source automated malware analysis system.
    - [Pylibemu](https://github.com/buffer/pylibemu) - A Libemu Cython wrapper.
    - [RFISandbox](https://monkey.org/~jose/software/rfi-sandbox/) - a PHP 5.x script sandbox built on top of [funcall](https://pecl.php.net/package/funcall)  
    - [dorothy2](https://github.com/m4rco-/dorothy2) - A malware/botnet analysis framework written in Ruby
    - [imalse](https://github.com/hbhzwj/imalse) - Integrated MALware Simulator and Emulator.
    - [libemu](https://github.com/buffer/libemu) - Shellcode emulation library, useful for shellcode detection.


- Sandbox-as-a-Service
    - [Hybrid Analysis](https://www.hybrid-analysis.com) - a free malware analysis service powered by Payload Security that detects and analyzes unknown threats using a unique Hybrid Analysis technology.
    - [Joebox Cloud](https://jbxcloud.joesecurity.org/login) - analyzes the behavior of malicious files including PEs, PDFs, DOCs, PPTs, XLSs, APKs, URLs and MachOs on Windows, Android and Mac OS X for suspicious activities.
    - [VirusTotal](https://www.virustotal.com/)
    - [detux.org](https://detux.org) - Multiplatform Linux Sandbox.
    - [malwr.com](https://malwr.com/) - free malware analysis service and community.

## <a name="visualizers"></a> Data Tools

- Front Ends
    - [DionaeaFR](https://github.com/rubenespadas/DionaeaFR) - Front Web to Dionaea low-interaction honeypot.
    - [Django-kippo](https://github.com/jedie/django-kippo) - Django App for kippo SSH Honeypot.
    - [Shockpot-Frontend](https://github.com/GovCERT-CZ/Shockpot-Frontend) - a full featured script to visualize statistics from a Shockpot honeypot. 
    - [Tango](https://github.com/aplura/Tango) - Honeypot Intelligence with Splunk.
    - [Wordpot-Frontend](https://github.com/GovCERT-CZ/Wordpot-Frontend) - a full featured script to visualize statistics from a Wordpot honeypot.
    - [honeyalarmg2](https://github.com/schmalle/honeyalarmg2) - Simplified UI for showing honeypot alarms.
    - [honeypotDisplay](https://github.com/Joss-Steward/honeypotDisplay) - A flask website which displays data I've gathered with my SSH Honeypot. 

- Visualization
    - [Acapulco](https://github.com/hgascon/acapulco) - Automated Attack Community Graph Construction.
    - [Afterglow Cloud](https://github.com/ayrus/afterglow-cloud)
    - [Afterglow](http://afterglow.sourceforge.net/)
    - [Glastopf Analytics](https://github.com/katkad/Glastopf-Analytics) - easy honeypot statistics
    - [HoneyMalt](https://github.com/SneakersInc/HoneyMalt) - Maltego tranforms for mapping Honeypot systems.
    - [HoneyMap](https://github.com/fw42/honeymap) - Real-time websocket stream of GPS events on a fancy SVG world map. 
    - [HoneyStats](https://sourceforge.net/projects/honeystats/) - A statistical view of the recorded activity on a Honeynet. 
    - [HpfeedsHoneyGraph](https://github.com/yuchincheng/HpfeedsHoneyGraph) - a visualization app to visualize hpfeeds logs.
    - [Kippo stats](https://github.com/mfontani/kippo-stats) - Mojolicious app to display statistics for your kippo SSH honeypot. 
    - [Kippo-Graph](https://bruteforcelab.com/kippo-graph) - a full featured script to visualize statistics from a Kippo SSH honeypot.
    - [Sebek Dataviz](http://www.honeynet.org/gsoc/project4) - Sebek data visualization.
    - [The Intelligent HoneyNet](https://github.com/jpyorre/IntelligentHoneyNet) - The Intelligent Honey Net Project attempts to create actionable information from honeypots.
    - [ovizart](https://github.com/oguzy/ovizart) - visual analysis for network traffic. 

## <a name="guides"></a>Guides

- [T-Pot: A Multi-Honeypot Platform](https://dtag-dev-sec.github.io/mediator/feature/2015/03/17/concept.html)
- [Honeypot (Dionaea and kippo) setup script](https://github.com/andrewmichaelsmith/honeypot-setup-script/)

- Deployment
    - [Dionaea and EC2 in 20 Minutes](http://andrewmichaelsmith.com/2012/03/dionaea-honeypot-on-ec2-in-20-minutes/) - a tutorial on setting up Dionaea on an EC2 instance
    - [Using a Raspberry Pi honeypot to contribute data to DShield/ISC](https://isc.sans.edu/diary/22680) - The Raspberry Pi based system will allow us to maintain one code base that will make it easier to collect rich logs beyond firewall logs.
    - [honeypotpi](https://github.com/free5ty1e/honeypotpi) - Script for turning a Raspberry Pi into a HoneyPot Pi

- Research Papers
    - [Honeypot research papers](https://github.com/shbhmsingh72/Honeypot-Research-Papers) - PDFs of research papers on honeypots
    - [vEYE](https://link.springer.com/article/10.1007%2Fs10115-008-0137-3) - behavioral footprinting for self-propagating worm detection and profiling.
