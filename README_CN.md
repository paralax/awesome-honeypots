# 最优秀的蜜罐列表

[![Awesome Honeypots](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

优秀的蜜罐、组件等等相关的工具列表，分为 Web、服务等多个类别，重点放在开源项目上

每个类别中没有顺序，按照提交的先后顺序排列，如果您也想提交，请阅读 [指南](CONTRIBUTING.md).

探索更多优秀的列表请参阅：[sindresorhus/awesome](https://github.com/sindresorhus/awesome).

### 目录

- [蜜罐](#honeypots)
- [Honeyd 工具](#honeyd)
- [网络与行为分析](#analysis)
- [数据分析工具](#visualizers)
- [指南](#guides)

## Related Lists
- [awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools) 网络流量分析
- [awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis) 与上表有些重复，更侧重恶意软件分析

## <a name="honeypots"></a> 蜜罐

- 数据库蜜罐
    - [MongoDB-HoneyProxy](https://github.com/Plazmaz/MongoDB-HoneyProxy) - MongoDB 蜜罐代理
    - [Elastic honey](https://github.com/jordan-wright/elastichoney) - 简单的 Elasticsearch 蜜罐
    - [mysql](https://github.com/schmalle/MysqlPot) - mysql 蜜罐
    - [NoSQLpot](https://github.com/torque59/nosqlpot) - NoSQL 蜜罐框架
    - [ESPot](https://github.com/mycert/ESPot) - 一个用 NodeJS 编写的 Elasticsearch 蜜罐，用于对 CVE-2014-3120 的利用
    - [Delilah](https://github.com/SecurityTW/delilah) - Python 编写的 Elasticsearch 蜜罐
    - [mysql-honeypotd](https://github.com/sjinks/mysql-honeypotd) - C 编写的低交互 MySQL 蜜罐

- Web 蜜罐
    - [Glastopf](https://github.com/mushorg/glastopf) - Web 应用蜜罐
    - Snare/Tanner - Glastopf 的后继者
      - [Snare](https://github.com/mushorg/snare) - 下一代高交互 honEypot
      - [Tanner](https://github.com/mushorg/tanner) - 评估 SNARE 事件
    - [phpmyadmin_honeypot](https://github.com/gfoss/phpmyadmin_honeypot) - - 简单有效的 phpMyAdmin 蜜罐
    - [Nodepot](https://github.com/schmalle/Nodepot)  - nodejs Web 应用蜜罐
    - [basic-auth-pot](https://github.com/bjeborn/basic-auth-pot) bap - HTTP 基本认证蜜罐
    - [Shadow Daemon](https://shadowd.zecure.org/overview/introduction/) - 用于 PHP、Perl 和 Python 应用程序的模块化Web应用程序防火墙/高交互式蜜罐
    - [Servletpot](https://github.com/schmalle/servletpot) - Web 应用蜜罐
    - [Google Hack Honeypot](http://ghh.sourceforge.net) - 旨在提供针对那些使用搜索引擎探测资源的攻击者的侦察
    - [smart-honeypot](https://github.com/freak3dot/smart-honeypot) - PHP 脚本编写的智能蜜罐
    - [Bukkit Honeypot](https://github.com/Argomirr/Honeypot) Honeypot - Bukkit 的一个插件
    - [Laravel Application Honeypot](https://github.com/msurguy/Honeypot) - Honeypot - Laravel 应用程序的简单垃圾邮件预防软件包
    - [stack-honeypot](https://github.com/CHH/stack-honeypot) - 将针对垃圾邮件机器人的陷阱插入到响应中
    - [EoHoneypotBundle](https://github.com/eymengunay/EoHoneypotBundle) - Symfony2 类型的蜜罐
    - [shockpot](https://github.com/threatstream/shockpot) - 检测 Shell Shock 利用尝试的 Web 应用蜜罐
    - [django-admin-honeypot](https://github.com/dmpayton/django-admin-honeypot) - 虚假的 Django 管理登录页面，记录未经授权的访问尝试
    - WordPress 蜜罐
        - [HonnyPotter](https://github.com/MartinIngesen/HonnyPotter) - WordPress 的登录蜜罐，用于收集和分析失败的登录尝试
        - [HoneyPress](https://github.com/dustyfresh/HoneyPress) - Docker 容器中基于 Python 的 WordPress 蜜罐
        - [wp-smart-honeypot](https://github.com/freak3dot/wp-smart-honeypot) - 减少垃圾邮件的 WordPress 插件
        - [wordpot](https://github.com/gbrindisi/wordpot) - WordPress 蜜罐
    - [honeyhttpd](https://github.com/bocajspear1/honeyhttpd) - 基于 Python 的 Web 服务器蜜罐构建工具

- 服务蜜罐
    - [honeyntp](https://github.com/fygrave/honeyntp) - NTP 蜜罐
    - [honeypot-camera](https://github.com/alexbredo/honeypot-camera) - 相机蜜罐
    - [troje](https://github.com/dutchcoders/troje/) - 围绕 LXC 容器的蜜罐，将每一个服务的连接都放到单独的 LXC 容器内
    - [HoneyPy](https://github.com/foospidy/HoneyPy) - 低交互蜜罐
    - [Ensnare](https://github.com/ahoernecke/ensnare) - 易部署的 Ruby 蜜罐
    - [RDPy](https://github.com/citronneur/rdpy) - Python 实现的 RDP 蜜罐
    - [Honeyprint](https://github.com/glaslos/honeyprint) - 打印机蜜罐
    - [Tom's Honeypot](https://github.com/inguardians/toms_honeypot) - 低交互 Python 蜜罐
    - [Honeyport](https://github.com/securitygeneration/Honeyport) - Bash 和 Python 写成的简单 honeyport
    - [AMTHoneypot](https://github.com/packetflare/amthoneypot) - 针对 Intel 的 AMT 固件漏洞（CVE-2017-5689）的蜜罐
    - [Lyrebird](https://hub.docker.com/r/lyrebird/honeypot-base/) - 现代高交互蜜罐框架
    - [Honeygrove](https://github.com/UHH-ISS/honeygrove) - 基于 Twisted 的多用途、模块化蜜罐
    - [WebLogic honeypot](https://github.com/Cymmetria/weblogic_honeypot) - 在带有 Oracle WebLogic Server 的 Oracle Fusion Middleware 中检测 CVE-2017-10271 的低交互蜜罐
    - [MICROS honeypot](https://github.com/Cymmetria/micros_honeypot) - 在带有 Oracle Hospitality Simphony 的 Oracle Hospitality Applications (MICROS) 中检测 CVE-2018-2636 的低交互蜜罐
    - [honeytrap](https://github.com/honeytrap/honeytrap) - 用 Go 编写的高级蜜罐框架，可以连接其他蜜罐

- 分布式蜜罐
    - [DemonHunter](https://github.com/RevengeComing/DemonHunter) - 低交互蜜罐服务器

- 反蜜罐
    - [kippo_detect](https://github.com/andrew-morris/kippo_detect) - 检测 Kippo 蜜罐

- ICS/SCADA 蜜罐
    - [Conpot](https://github.com/mushorg/conpot) - ICS/SCADA 蜜罐
    - [gridpot](https://github.com/sk4ld/gridpot) - 模拟实际电网的开源蜜罐
    - [scada-honeynet](http://www.digitalbond.com/blog/2007/07/24/scada-honeynet-article-in-infragard-publication/) - 模拟流行的 PLC 服务，更好地帮助 SCADA 研究人员了解暴露的控制系统设备的潜在风险
    - [SCADA honeynet](http://scadahoneynet.sourceforge.net) - 建立工业网络的蜜罐
    - [GasPot](https://github.com/sjhilt/GasPot) - Veeder Root Gaurdian AST, 常见于石油、天然气行业

- 其他/随机
    - [NOVA](https://github.com/DataSoft/Nova) 看起来像完整系统的蜜罐
    - [OFPot](https://github.com/upa/ofpot) - 基于 POX 的 OpenFlow 蜜罐，将未使用的IP地址的流量重定向到蜜罐中
    - [OpenCanary](https://pypi.org/project/opencanary/) - 模块化、分布式蜜罐
    - [DSHP](https://github.com/naorlivne/dshp) - 带有插件化支持的简单蜜罐

- 僵尸网络 C&C 工具
    - [Hale](https://github.com/pjlantz/Hale) - 僵尸网络 C&C 监视器
    - [dnsMole](https://code.google.com/archive/p/dns-mole/) - 分析 DNS 流量，检测潜在的僵尸网络 C&C 服务器和受感染的主机

- IPv6 攻击检测工具
    - [ipv6-attack-detector](https://github.com/mzweilin/ipv6-attack-detector/)  - Honeynet 项目支持的 Googel Summer of Code 2012 项目

- 动态代码检查工具包
    - [Frida](https://www.frida.re) - 注入 JavaScript 来探索Windows、Mac、Linux、iOS 和 Android 上的应用程序

- 将网站转换为服务器蜜罐
    - [HIHAT](http://hihat.sourceforge.net/) - 将任意 PHP 页面转换成基于 Web 的高交互蜜罐

- 恶意软件收集
    - [Kippo-Malware](https://bruteforcelab.com/kippo-malware) - 用于在 Kippo SSH 蜜罐数据库中记录的 URL 上下载恶恶意文件的 Python 脚本

- 分布式传感器部署
    - [Modern Honey Network](https://github.com/threatstream/mhn) - 分布式 Snort 与蜜罐传感器管理，使用虚拟网络，最小指纹的 SNORT 安装，服务器提供隐形侦察与集中管理
    - [ADHD](https://sourceforge.net/projects/adhd/) - Active Defense Harbinger Distribution（ADHD）是基于 Ubuntu LTS 的 Linux 发行版，并配备了许多预装的主动防御工具

- 网络分析工具
    - [Tracexploit](https://code.google.com/archive/p/tracexploit/) - 重放网络数据包

- 日志匿名工具
    - [LogAnon](http://code.google.com/archive/p/loganon/) - 日志匿名库

- 低交互蜜罐（路由器后门）
    - [Honeypot-32764](https://github.com/knalli/honeypot-for-tcp-32764) - 路由器后门蜜罐(TCP 32764).

- HTTPS 代理
    - [mitmproxy](https://mitmproxy.org/) - 拦截、检查、修改、重放流量

- 系统插桩
    - [Sysdig](https://sysdig.com/opensource/) - 捕获 Linux 系统的状态与活动，可以进行保存、过滤与分析的开源系统级探索工具
    - [Fibratus](https://github.com/rabbitstack/fibratus) - 用于探索和跟踪 Windows 内核的工具

- 检测 USB 恶意传播的蜜罐
    - [Ghost-usb](https://github.com/honeynet/ghost-usb-honeypot) - 检测通过 USB 存储设备传播恶意软件的蜜罐

- 数据采集
    - [Kippo2MySQL](https://bruteforcelab.com/kippo2mysql) - 从 Kippo 的日志文件中提取一些基本的统计信息插入到数据库中
    - [Kippo2ElasticSearch](https://bruteforcelab.com/kippo2elasticsearch) - 用于将 Kippo SSH 蜜罐数据从 MySQL 数据库传输到 ElasticSearch 实例（服务器或集群）的 Python 脚本

- 被动网络审计框架解析工具
    - [pnaf](https://github.com/jusafing/pnaf) - 被动网络审计框架

- 虚拟机监控工具
    - [vmscope](https://cs.gmu.edu/~xwangc/Publications/RAID07-VMscope.pdf) - 基于虚拟机的监视
    - [vmitools](http://libvmi.com/) - 带有 Python 接口的 C 库，可以轻松监视运行中的虚拟机的底层细节
    - [Antivmdetect](https://github.com/nsmfoo/antivmdetection) - 用于创建 VirtualBox 虚拟机模版的脚本，使检测虚拟机更困难
    - [VMCloak](https://github.com/hatching/vmcloak) - Cuckoo 沙盒的自动虚拟机生成和隐藏

- 二进制调试器
    - [Hexgolems - Schem Debugger Frontend](https://github.com/hexgolems/schem) - 一个调试器前端
    - [Hexgolems - Pint Debugger Backend](https://github.com/hexgolems/pint) - 一个调试器后端与 Pin 的 Lua 接口

- 移动应用分析工具
    - [APKinspector](https://github.com/honeynet/apkinspector/) - 带有界面的安卓应用程序分析工具
    - [Androguard](https://github.com/androguard/androguard) - 安卓应用程序逆向工程工具

- 低交互蜜罐
    - [Honeyperl](https://sourceforge.net/projects/honeyperl/) - 基于 Perl 的蜜罐，有很多插件

- 蜜罐数据融合
    - [HFlow2](https://projects.honeynet.org/hflow) - 用于蜜罐/网络分析的数据融合工具

- 服务器
    - [LaBrea](http://labrea.sourceforge.net/labrea-info.html) - 接管未使用的 IP 地址，创建对蠕虫、黑客有吸引力的虚拟服务
    - [Honeysink](http://www.honeynet.org/node/773) - 开源网络陷阱，提供了检测与阻止指定网络上恶意流量的机制
    - [KFSensor](http://www.keyfocus.net/kfsensor/) - 基于 Windows 的入侵检测系统蜜罐
    - [Honeyd](https://github.com/provos/honeyd) Also see [more honeyd tools](#honeyd).
    - [UDPot Honeypot](https://github.com/jekil/UDPot) - 简单 UDP / DNS 蜜罐脚本
    - [Conpot](http://conpot.org/) - 低交互的工业控制系统蜜罐
    - [Bifrozt](https://github.com/Ziemeck/bifrozt-ansible) - 自动部署带有 ansible 的 bifrozt
    - [Bait and Switch](http://baitnswitch.sourceforge.net) - 将恶意流量重定向到生产系统镜像的蜜罐
    - [Artillery](https://github.com/trustedsec/artillery/) - 开源蓝队工具，旨在通过多种办法保护 Linux 和 Windows 操作系统
    - [slipm-honeypot](https://github.com/rshipp/slipm-honeypot) - 简单的低交互端口监听蜜罐
    - [HoneyWRT](https://github.com/CanadianJeff/honeywrt) - 基于 Python 的低交互蜜罐，旨在模拟攻击者可能攻击的服务或端口
    - [Amun](http://amunhoney.sourceforge.net) - 漏洞模拟蜜罐
    - [TelnetHoney](https://github.com/balte/TelnetHoney) - 简单的 telnet 蜜罐
    - [Hontel](https://github.com/stamparm/hontel) - Telnet 蜜罐
    - [MTPot](https://github.com/Cymmetria/MTPot) - 专注于 Mirai 的开源 Telnet 蜜罐
    - [Heralding](https://github.com/johnnykv/heralding) - 捕获凭据的蜜罐
    - [vnclowpot](https://github.com/magisterquis/vnclowpot) - 低交互的 VNC 蜜罐
    - [SIREN](https://github.com/blaverick62/SIREN) - 半智能蜜罐网络 - 蜜网只能虚拟环境
    - [telnetlogger](https://github.com/robertdavidgraham/telnetlogger) - 跟踪 Mirai 的 Telnet 蜜罐
    - [honeytrap](https://github.com/tillmannw/honeytrap) - 一个用于捕获针对 TCP 和 UDP 服务攻击的低交互蜜罐
    - [mwcollectd](https://www.openhub.net/p/mwcollectd) - 联合 nepenthes 和 honeytrap 的最佳功能实现的多功能恶意软件收集蜜罐
    - [portlurker](https://github.com/bartnv/portlurker) - 用于协议猜测和安全字符显示的端口监听工具/蜜罐
    - [arctic-swallow](https://github.com/ajackal/arctic-swallow) - 低交互蜜罐
    - [glutton](https://github.com/mushorg/glutton) - 可喂食蜜罐

- IDS 签名生成
    - [Honeycomb](http://www.icir.org/christian/honeycomb/) - 使用蜜罐自动创建签名

- 查找服务提供商的 ASN 与前缀
    - [CC2ASN](http://www.cc2asn.com/) - 简单的查询服务

- Thug 的 Web 界面
    - [Rumal](https://github.com/thugs-rumal/) - Thug 的界面

- 数据收集/数据共享
    - [HPfriends](http://hpfriends.honeycloud.net/#/home) - 蜜罐数据共享平台
      - [hpfriends - real-time social data-sharing](https://heipei.io/sigint-hpfriends/) - HPFriends 订阅系统的展示
    - [HPFeeds](https://github.com/rep/hpfeeds/) - 轻量认证的订阅发布协议

- 集中管理工具
    - [PHARM](http://www.nepenthespharm.com/) - 管理、统计、分析你的分布式 Nepenthes 蜜罐

- 网络连接分析工具
    - [Impost](http://impost.sourceforge.net/) - 网络安全审计工具，用于取证分析被破坏/易受攻击的守护进程

- 蜜罐部署
    - [Modern Honeynet Network](http://threatstream.github.io/mhn/) - 让蜜罐的管理与部署更简单

- Wireshark 的蜜罐扩展
    - [Whireshark Extensions](https://www.honeynet.org/project/WiresharkExtensions) - 支持应用针对 PCAP 文件的 Snort IDS 规则与签名


- 客户端蜜罐
    - [Pwnypot](https://github.com/shjalayeri/pwnypot) - 高交互客户端蜜罐
    - [MonkeySpider](http://monkeyspider.sourceforge.net)
    - [Capture-HPC-NG](https://github.com/CERT-Polska/HSN-Capture-HPC-NG)
    - [URLQuery](https://urlquery.net/)
    - [Trigona](https://www.honeynet.org/project/Trigona)
    - [Thug](https://buffer.github.io/thug/)
    - [Shelia](https://www.cs.vu.nl/~herbertb/misc/shelia/)
    - [PhoneyC](https://github.com/honeynet/phoneyc)
    - [Jsunpack-n](https://github.com/urule99/jsunpack-n)
    - [HoneyC](https://projects.honeynet.org/honeyc)
    - [HoneyBOT](http://www.atomicsoftwaresolutions.com/)
    - [CWSandbox / GFI Sandbox](https://www.gfi.com/products-and-solutions/all-products)
    - [Capture-HPC-Linux](https://redmine.honeynet.org/projects/linux-capture-hpc/wiki)
    - [Capture-HPC](https://projects.honeynet.org/capture-hpc) - 高交互客户端蜜罐
    - [YALIH (Yet Another Low Interaction Honeyclient)](https://github.com/Masood-M/yalih) - 低交互客户端蜜罐，旨在通过签名，异常和模式匹配技术检测恶意网站

- 蜜罐
    - [Single-honeypot](https://sourceforge.net/projects/single-honeypot/)
    - [IMHoneypot](https://github.com/mushorg/imhoneypot)
    - [Deception Toolkit](http://www.all.net/dtk/dtk.html)

- PDF 文档检查工具
    - [peepdf](https://github.com/jesparza/peepdf)

- 分布式系统
    - [Thug Distributed Task Queuing](https://thug-distributed.readthedocs.io/en/latest/index.html)

- HoneyClient Management
    - [HoneyWeb](https://code.google.com/archive/p/gsoc-honeyweb/)

- 混合低/高交互蜜罐
    - [HoneyBrid](http://honeybrid.sourceforge.net)

- SSH 蜜罐
    - [Kojoney](http://kojoney.sourceforge.net/)
    - [Kojoney2](https://github.com/madirish/kojoney2) - 根据 Kojoney 用 Python 编写的低交互 SSH 蜜罐
    - [Kippo](https://github.com/desaster/kippo) - 中交互 SSH 蜜罐
       - [LongTail Log Analysis @ Marist College](http://longtail.it.marist.edu/honey/) - 分析 SSH 蜜罐日志
    - [Cowrie](https://github.com/cowrie/cowrie) - Cowrie SSH 蜜罐 (基于 kippo)
    - [sshlowpot](https://github.com/magisterquis/sshlowpot) - Go 编写的低交互 SSH 蜜罐
    - [sshhipot](https://github.com/magisterquis/sshhipot) - 高交互中间人 SSH 蜜罐
    - [DShield docker](https://github.com/xme/dshield-docker) - 启用了 DShield 输出的 Docker 容器
    - [hornet](https://github.com/czardoz/hornet) - 支持多虚拟主机的中交互 SSH 蜜罐
    - [ssh-honeypot](https://github.com/droberson/ssh-honeypot) - 伪造 SSHD，记录 IP 地址、用户名与密码
    - [Kippo_JunOS](https://github.com/gregcmartin/Kippo_JunOS) - 基于 Kippo 的蜜罐
    - [ssh-honeypotd](https://github.com/sjinks/ssh-honeypotd) - C 编写的低交互 SSH 蜜罐
    - [sshesame](https://github.com/jaksi/sshesame) - 记录登录活动的虚假 SSH 服务器
    - [sshsyrup](https://github.com/mkishere/sshsyrup) - 简单的 SSH 蜜罐，捕获终端活动并上传到 asciinema.org

- 分布式传感器项目
    - [DShield Web Honeypot Project](https://sites.google.com/site/webhoneypotsite/)

- PCAP 分析工具
    - [Honeysnap](https://projects.honeynet.org/honeysnap/)

- 客户端 Web 爬虫
    - [HoneySpider Network](https://github.com/CERT-Polska/hsn2-bundle)

- 网络流量重定向工具
    - [Honeywall](https://projects.honeynet.org/honeywall/)

- 混合内容的分布式蜜罐
    - [HoneyDrive](https://bruteforcelab.com/honeydrive)

- 蜜罐传感器
    - [Honeeepi](https://redmine.honeynet.org/projects/honeeepi/wiki) - Raspberry Pi 上一款基于定制 Raspbian 操作系统的蜜罐

- File carving
    - [TestDisk & PhotoRec](https://www.cgsecurity.org/)

- Sebek
    - [Sebek](https://projects.honeynet.org/sebek/) - 数据捕获
    - [Qebek](https://projects.honeynet.org/sebek/wiki/Qebek) - 基于 QEMU 的 Sebek
    - [xebek](https://code.google.com/archive/p/xebek/) - Xen 上的 Sebek

- SSH 代理
    - [HonSSH](https://github.com/tnich/honssh)

- Windows 可用的行为分析工具
    - [Capture BAT](https://www.honeynet.org/node/315)

- Live CD
    - [DAVIX](https://www.secviz.org/node/89) - DAVIX Released 

- Spamtrap
    - [Mailoney](https://github.com/awhitehatter/mailoney) - Python 编写的 SMTP 蜜罐，具有开放中继、凭据记录等功能
    - [Spamhole](http://www.spamhole.net/)
    - [spamd](http://man.openbsd.org/cgi-bin/man.cgi?query=spamd%26apropos=0%26sektion=0%26manpath=OpenBSD+Current%26arch=i386%26format=html)
    - [Mail::SMTP::Honeypot](https://metacpan.org/pod/release/MIKER/Mail-SMTP-Honeypot-0.11/Honeypot.pm) - 提供标准 SMTP 服务器工具的 Perl 模块
    - [honeypot](https://github.com/jadb/honeypot) - 蜜罐项目组非官方 PHP 的 SDK
    - [SpamHAT](https://github.com/miguelraulb/spamhat) - 垃圾邮件蜜罐工具
    - [SendMeSpamIDS.py](https://github.com/johestephan/VerySimpleHoneypot) - 获得所有 IDS 和分析设备的简单 SMTP
    - [Shiva](https://github.com/shiva-spampot/shiva) - 垃圾邮件蜜罐与智能分析工具
        - [Shiva The Spam Honeypot Tips And Tricks For Getting It Up And Running](https://www.pentestpartners.com/security-blog/shiva-the-spam-honeypot-tips-and-tricks-for-getting-it-up-and-running/)

- 商业蜜网
    - [Cymmetria Mazerunner](https://cymmetria.com/products/mazerunner/) - MazeRunner 可引导攻击者远离真实目标，并创建攻击痕迹跟踪

- 服务器（蓝牙）
    - [Bluepot](https://github.com/andrewmichaelsmith/bluepot)

- Android 应用程序动态分析
    - [Droidbox](https://code.google.com/archive/p/droidbox/)

- Docker 化的低交互蜜罐
    - [Manuka](https://github.com/andrewmichaelsmith/manuka) - 基于 Docker 的蜜罐 (Dionaea & Kippo).
    - [Dockerized Thug](https://hub.docker.com/r/honeynet/thug/) - 基于 [Thug](https://github.com/buffer/thug) 的 Docker 蜜罐，用于分析恶意 Web 内容
    - [Dockerpot](https://github.com/mrschyte/dockerpot) - 基于 Docker 的蜜罐
    - [Docker honeynet](https://github.com/sreinhardt/Docker-Honeynet) - 部署与 Docker 容器中的一些蜜网工具
    - [mhn-core-docker](https://github.com/MattCarothers/mhn-core-docker) - 在 Docker 中实现的现代蜜网核心元素

- 网络分析
    - [Quechua](https://bitbucket.org/zaccone/quechua)

- SIP Server
    - [Artemnesia VoIP](http://artemisa.sourceforge.net)

    
- IOT 蜜罐
    - [HoneyThing](https://github.com/omererdem/honeything) - TR-069 蜜罐

- Honeytokens
    - [Honeyλ](https://github.com/0x4D31/honeylambda) - 简单的无服务器应用程序，旨在创建和监控 AWS Lambda 和 Amazon API Gateway 之上的网址 honeytokens
    - [Honeybits](https://github.com/0x4D31/honeybits) - 旨在通过在生产服务器和工作站中传播 breadcrumbs 和 honeytokens 来诱使攻击者进入蜜罐，从而提高诱捕率
    - [CanaryTokens](https://github.com/thinkst/canarytokens)
    - [dcept](https://github.com/secureworks/dcept) - 部署、检测活动目录使用情况的 honeytokens

## <a name="honeyd"></a> Honeyd 工具

- Honeyd 插件
    - [Honeycomb](http://www.honeyd.org/tools.php)

- Honeyd 查看工具
    - [Honeyview](http://honeyview.sourceforge.net/)

- Honeyd 与 MySQL 的连接
    - [Honeyd2MySQL](https://bruteforcelab.com/honeyd2mysql)

- Honeyd 统计数据可视化脚本
    - [Honeyd-Viz](https://bruteforcelab.com/honeyd-viz)

- Honeyd UI
    - [Honeyd configuration GUI](http://www.citi.umich.edu/u/provos/honeyd/ch01-results/1/) - 用于配置honeyd守护进程并生成配置文件的程序

- Honeyd 统计
    - [Honeydsum.pl](https://github.com/DataSoft/Honeyd/blob/master/scripts/misc/honeydsum-v0.3/honeydsum.pl)



## <a name="analysis"></a> 网络与行为分析

- 沙盒
    - [RFISandbox](https://monkey.org/~jose/software/rfi-sandbox/) - 使用 PHP 5.x 脚本在 [funcall](https://pecl.php.net/package/funcall) 上构建的沙盒
    - [dorothy2](https://github.com/m4rco-/dorothy2) - Ruby 编写的恶意软件/僵尸网络分析框架
    - [COMODO automated sandbox](https://help.comodo.com/topic-72-1-451-4768-.html)
    - [Argos](http://www.few.vu.nl/argos/) - 用于捕获零日攻击的模拟器
    - [libemu](https://github.com/buffer/libemu) - Shellcode 模拟库，对 Shellcode 检测十分有用
    - [Pylibemu](https://github.com/buffer/pylibemu) - Libemu Cython 
    - [imalse](https://github.com/hbhzwj/imalse) - 集成的恶意软件仿真工具与模拟工具
    - [Cuckoo](https://cuckoosandbox.org/) - 领先的开源自动化恶意软件分析系统

- 沙盒即服务
    - [malwr.com](https://malwr.com/) - 提供免费恶意软件分析服务与社区
    - [Joebox Cloud](https://jbxcloud.joesecurity.org/login) - 确定 Windows、Android 和 Mac OS X 上的恶意文件（包括PE、PDF、DOC、PPT、XLS、APK、URL 和 MachO）的行为，判断其是否存在可疑活动
    - [VirusTotal](https://www.virustotal.com/)
    - [Hybrid Analysis](https://www.hybrid-analysis.com) - 由 Payload Security 提供的免费恶意软件分析服务，可使用其独特的混合分析技术检测和分析未知威胁

## <a name="visualizers"></a> 数据分析工具

- 前端
    - [Tango](https://github.com/aplura/Tango) - 使用 Splunk 处理蜜罐情报
    - [Django-kippo](https://github.com/jedie/django-kippo) - 用于 kippo SSH 蜜罐的 Django 程序
    - [Wordpot-Frontend](https://github.com/GovCERT-CZ/Wordpot-Frontend) - 用于可视化 Wordpot 蜜罐中数据的脚本
    - [Shockpot-Frontend](https://github.com/GovCERT-CZ/Shockpot-Frontend) - 用于可视化 Shockpot 蜜罐中数据的脚本
    - [honeypotDisplay](https://github.com/Joss-Steward/honeypotDisplay) - 展示 SSH 蜜罐的 Flask 网站
    - [honeyalarmg2](https://github.com/schmalle/honeyalarmg2) - 用于显示蜜罐数据的简化 UI
    - [DionaeaFR](https://github.com/rubenespadas/DionaeaFR) - Dionaea 蜜罐前端 Web

- 可视化
    - [Kippo-Graph](https://bruteforcelab.com/kippo-graph) - 用于可视化 Kippo 蜜罐中数据的脚本
    - [Kippo stats](https://github.com/mfontani/kippo-stats) - 为 kippo SSH 蜜罐展示数据的程序
    - [HoneyStats](https://sourceforge.net/projects/honeystats/) - Honeynet 的统计视图
    - [HoneyMap](https://github.com/fw42/honeymap) - 显示实时 Websocket 流的 SVG 地图
    - [HoneyMalt](https://github.com/SneakersInc/HoneyMalt) - Maltego 转换映射蜜罐系统
    - [Glastopf Analytics](https://github.com/katkad/Glastopf-Analytics) - 简单蜜罐统计
    - [Afterglow Cloud](https://github.com/ayrus/afterglow-cloud)
    - [Afterglow](http://afterglow.sourceforge.net/)
    - [ovizart](https://github.com/oguzy/ovizart) - 可视化网络流量分析
    - [HpfeedsHoneyGraph](https://github.com/yuchincheng/HpfeedsHoneyGraph) - 可视化 hpfeeds 日志的程序
    - [Acapulco](https://github.com/hgascon/acapulco) - 自动攻击群体图构建
    - [Sebek Dataviz](http://www.honeynet.org/gsoc/project4) - Sebek 数据可视化
    - [The Intelligent HoneyNet](https://github.com/jpyorre/IntelligentHoneyNet) - 试图创建蜜罐中可操作信息的智能蜜网项目

## <a name="guides"></a> 指南

- [T-Pot: 多蜜罐平台](https://dtag-dev-sec.github.io/mediator/feature/2015/03/17/concept.html)
- [蜜罐 (Dionaea and kippo) 设置脚本](https://github.com/andrewmichaelsmith/honeypot-setup-script/)

- 部署
    - [Dionaea and EC2 in 20 Minutes](http://andrewmichaelsmith.com/2012/03/dionaea-honeypot-on-ec2-in-20-minutes/) - 在 EC2 上设置 Dionaea 的教程
    - [honeypotpi](https://github.com/free5ty1e/honeypotpi) - 将 Raspberry Pi 变成 HoneyPot Pi 的脚本
    - [Using a Raspberry Pi honeypot to contribute data to DShield/ISC](https://isc.sans.edu/diary/22680) - 基于 Raspberry Pi 的系统可以收集比防火墙日志更丰富的日志

- 研究论文
    - [vEYE](https://link.springer.com/article/10.1007%2Fs10115-008-0137-3) - 自传播蠕虫行为痕迹的检测与分析
