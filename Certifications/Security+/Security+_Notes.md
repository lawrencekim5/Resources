

# 1.0 Threats, Attacks and Vulnerabilities
### 1.1 Given a scenario, analyze indicators of compromise and determine the type of malware.

**Viruses**

**Crypto-malware**

**Ransomware**

**Worm**

**Trojan**

**Rootkit**

**Keylogger**

**Adware**

**Spyware**

**Bots**

**RAT**

**Logic bomb**

**Backdoor**


### 1.2 Compare and contrast types of attacks.

**Social engineering**

- Phishing
- Spear phishing
- Whaling
- Vishing
- Tailgating
- Impersonation
- Dumpster diving
- Shoulder surfing
- Hoax
- Watering hole attack
- Principles (reasons for effectiveness)
   - Authority
   - Intimidation
   - Consensus
   - Scarcity
   - Familiarity
   - Trust
   - Urgency

**Application/service attacks**

- DoS
- DDoS
- On-path attack (previously known as man-in-the-middle attack/man-in-the-browser attack)
- Buffer overflow
- Injection
- Cross-site scripting
- Cross-site request forgery
- Privilege escalation
- ARP poisoning
- Amplification
- DNS poisoning

      AKA DNS cache poisoning. Attackers modify the A or AAAA record of a DNS cache, changing the IP address with a bogus IP address.
      This will redirect users to the malicious site. 

- Domain hijacking
- Zero day
- Replay
- Pass the hash
- Hijacking and related attacks
   - Clickjacking
   - Session hijacking
   - URL hijacking
   - Typo squatting
- Driver manipulation
   - Shimming
   - Refactoring
- MAC spoofing
- IP spoofing

**Wireless attacks**

- Replay
- IV
- Evil twin
- Rogue AP
- Jamming
- WPS
- Bluejacking
- Bluesnarfing
- RFID
- NFC
- Disassociation

**Cryptographic attacks**

- Birthday
- Known plain text/cipher text
- Rainbow tables
- Dictionary
- Brute force
   - Online vs. offline
- Collision
- Downgrade
- Replay
- Weak implementations


### 1.3 Explain threat actor types and attributes.
**Types of actors**
- Script kiddies
- Hacktivist
- Organized crime
- Nation states/APT
- Insiders
- Competitors

**Attributes of actors**
- Internal/external
- Level of sophistication
- Resources/funding
- Intent/motivation

**Use of open-source intelligence**

### 1.4 Explain penetration testing concepts.

**Active reconnaissance**

**Passive reconnaissance**

**Pivot**

**Initial exploitation**

**Persistence**

**Escalation of privilege**

**Unknown environment**

**Known environment**

**Partially known environment**

**Penetration testing vs. vulnerability scanning**


### 1.5 Explain vulnerability scanning concepts.
**Passively test security controls**

**Identify vulnerability**

**Identify lack of security controls**

**Identify common misconfigurations**

**Intrusive vs. non-intrusive**

**Credentialed vs. non-credentialed**

**False positive**


### 1.6 Explain the impact associated with types of vulnerabilities.

**Race conditions**

**Vulnerabilities due to:**

- End-of-life systems
- Embedded systems
- Lack of vendor support

**Improper input handling**

**Improper error handling**

**Misconfiguration/weak configuration**

**Default configuration**

**Resource exhaustion**

**Untrained users**

**Improperly configured accounts**

**Vulnerable business processes**

**Weak cipher suites and implementations**

**Memory/buffer vulnerability**
- Memory leak
- Integer overflow
- Buffer overflow
- Pointer dereference
- DLL injection

**System sprawl/undocumented assets**

**Architecture/design weaknesses**

**New threats/zero day**

**Improper certificate and key management**


# 2.0 Technologies and Tools
### 2.1 Install and configure network components, both hardwareand software-based, to support organizational security.

**Firewall**

- ACL

      Blocks specific types of traffic based on IP addresses, port numbers, and protocols.

- Application-based vs. network-based

      Application-based firewalls are software running on a system. These are often host-based. Network-based firewalls are
      dedicated systems that have additional software to monitor, filter, and log traffic. These have two or more NICs and
      are located at the broder of a network, between the Intranet (internal network) and the Internet.

- Stateful vs. stateless

      Stateless firewalls block traffic based on a ACL. Stateful firewalls keeps track of sessions and inspects traffic based
      on its state during a session. Ex: TCP sessions start with a 3-way handshake. If a stateful firewall detects TCP traffic
      without this handshake, it is recognized as suspicious traffic and is blocked.
  
- Implicit deny

      Implicit deny indicates that traffic that is not explicitly approved is implicitly denied. Ex: a single rule that allows HTTPS
      will block all other traffic if the implicit deny rule is enabled. Is always the last rule in the ACL. "DENY ANY ANY" or"DENY ALL ALL"

**VPN concentrator**

- Remote access vs. site-to-site
- IPSec
   - Tunnel mode
   - Transport mode
   - AH
   - ESP
- Split tunnel vs. full tunnel
- TLS
- Always-on VPN

**NIPS/NIDS**

      NIDS/NIPS are additional software designed to protect networks. Monitors network traffic and protects against
      network-based attacks. Can use taps and port mirrors to capture traffic. Can not monitor encrypted traffic or
      traffic on individual hosts.

- Signature-based

      AKA definition-based. Uses a database of known vulnerabilities or attack patterns. Similar to how anti-virus software
      uses signatures to detect malware. Signatures must be updated to protect against new threats.

- Heuristic/behavioral

      AKA anomaly-based detecction. Starts by identifying a baseline for normal operation or behavior by creating a performance baseline
      under normal operating conditions.

- Anomaly

      AKA heuristic based detection

- Inline vs. passive

      IPSs are inline, or in-band, with traffic. All traffic passes through the IPS and the IPS can block malicious traffic.
      IDSs are passive, or out-of-band, with traffic. An IDS monitors network traffic, but the traffic does not go through the IDS.

- In-band vs. out-of-band
- Rules

      IDSs reports events based on configured rules by administrators. Should be strict enough to not allow false negatives
      but not too strict to minimize false positives.

- Analytics
   - False positive

         Alert or alarm that is non threatening.

   - False negative

         Failure to alert or alarm a threat.

**Router**

      Routers connect multiple network segments into a single network and routes traffic between the segments. 

- ACLs

      Rules implemented on firewalls and routers to determine what traffic is allowed or denied. Router ACLs can block
      packets based on:
      - IP addresses and networks: block traffic from specific computers using IP addresses and subnets
      - Ports: block incoming or outgoing traffic on ports like blocking incoming HTTP but allowing outgoing HTTP on TCP 80
      - Protocol numbers: ICMP uses port 1 and is commonly used for DoS attacks. Can block ports to prevent abuse.

- Antispoofing

      Attackers spoof by replacing their source IP address with a different one in order to impersonate someone else. Antispoofing
      can be implemented by modifying the ACL to block specific IP addresses. Ex: private IP addresses are only used on private networks.
      As such, spoofed private IP addressed can be blocked using the following ACL rule:
      deny ip 10.0.0.0 0.255.255.255 any
      deny ip 172.16.0.0 0.15.255.255 any
      deny ip 192.168.0.0 0.0.255.255 any

**Switch**

      Learns what computers are attached to its physical ports. It uses this knowledge to create internal switched connections
      when two computers communicate with each other.

- Port security

      Port security limits the computers that connect to physical ports on a switch. This is done by disabling unused physical ports to prevent
      unauthorized connections or by using MAC filtering to block traffic from unfamiliar MAC addresses.

- Layer 2 vs. Layer 3

      Traditional sitches are Layer 2 devices. The destination MAC address in packets is used to determine the destination port.
      Routers are Layer 3 devices. They forward traffic based on the destination IP in a packet and block broadcast traffic.
      A Layer 3 switch mimics router behavior and allows network administrators to create VLANS. It is also protected against ARP
      attacks because it uses destination IP adresses, not destination MAC addresses.

- Loop prevention

      Switch loops can have similar effects to broadcast storms, potentially disabling switches and degrading performance. Switches can be looped
      by connecting two ports of the switch together, causing it to send and resent unicast transmissions to itself.
      STP (Spanning Tree Protocol) and RSTP (Rapid STP) are protocols that enable loop protection.

- Flood guard

      MAC flood attacks attempt to overload a switch with different MAC addresses associated with each physical port. Typically, the
      switch maps each MAC address to its physical port. A MAC fLood attack sends a large amount of traffic with spoofed MAC addresses
      to the same port. This causes the switch to run out of memory, reverting to a fail-open state, essentially working as a hub instead
      of a switch. Traffic sent to any port of the switch is now sent to all switch ports, allowing an attacker to connect a protocol
      analyzer to any port in order to collect all traffic in the switch.
      
      Flood guards protect against MAC flood attacks by limiting the amount of memory used to store MAC addresses for each port. Switches
      raise an alert when the limit is reached, sending a SNMP error message. A flood guard can also limit the max number of MAC addresses
      supported by a port. This is typically 1, but bridged VMs could access networks using the VM's MAC address but the NIC of the host, 
      in which case the setting should be set to 2.

**Proxy**
      
- Forward and reverse proxy

      A proxy borders the Internet and the Intranet. 
      Forward proxies forward requests for services from clients. Can improve performance through caching
      and can also restrict user access to content through filtering.
      Reverse proxies accept requests from the Internet. It appears to clients as a webserver, but is actually jsut
      forwarding and returning requests sent to the web server. Used to protect a web server.


- Transparent

      Transparent proxies accepts and forwards requests without modifying them. Simplest to set-up and use. Provides caching.
      Nontransparent proxies can modify and filter requests to block user access to certain sites. URL filters are used
      to let the proxy know what sites to restrict.

- Application/multipurpose

      Application proxies are used for specific applications. Accepts requests, forwards requests to the appropraite server,
      and returns requests to the original requestor. A forward proxy for HTTP is a basic application proxy. Most application proxies
      are multipurposeand can support multiple protocols like HTTP and HTTPS.

**Load balancer**

- Scheduling
   - Affinity
   - Round-robin
- Active-passive
- Active-active
- Virtual IPs

**Access point**

- SSID

      A Service Set Identifier is the name of the wireless network. Older APs have default SSIDs (Ex: Linkys). Newer APs
      force users to enter a name which is more secure because it gives attackers less information.
      SSID is broadcast to make it easy for wireless devices to find each other. Disabling SSID broadcast hides the SSID, but 
      only hides the network from casual users (security through obscurity). Attackers can still use a wireless protocol analyzer
      to find the SSID even if SSID broadcast is disabled.

- MAC filtering

      All NICs have a MAC address or physical address. MAC filtering can limit the accessibility of a network to only specific MAC addresses.
      However, attackers can use wireless sniffers to easily see allowed MAC addresses and spoof their address to match the MAC filter.

- Signal strength

      Ranges of APs can be limited to specific rooms or buildings by reducing the APs power level. 

- Band selection/width

      Wireless networks use two primary radio bands: 2.4 GHz and 5 GHz. Devices transmit GHz close to these numbers. 
      Band width refers to the width of the channel. Wider channels allow more data through, but decreases the distance
      of radio transmissions and also increases the possibility of interference.
      APs allow you to select which frequency band to use. 2.4 GHz is often used by bluetooth, microwaves, phones, and 
      has more potential for interference.

- Antenna types and placement

      Omnidirectional atennas transmit and receive signals from all directions. A directional atenna transmits and receives signals
      in a single direction and can do so over greater distances. 

- Fat vs. thin

      Fat access points ara AKA stand-alone, intelligent, or autonomous APs. They contain everything needed to connect wireless clients
      to a wireless network. Includes a routing component, NAT, DHCP, ACLs, etc. Indepently managed. Often used in home networks and small
      offices.
      Thin APs are controller-based and are not stand-alone. Administrators can use a wireless controller to manage all thin APs from one place.

- Controller-based vs. standalone

      Controller-based are thin APs. They are not stand-alone and must be managed. Standalone APs are fat and do everything and must be independently managed.

**SIEM**

- Aggregation
- Correlation
- Automated alerting and triggers
- Time synchronization
- Event deduplication
- Logs/WORM

**DLP**

- USB blocking
- Cloud-based
- Email

**NAC**

- Dissolvable vs. permanent
- Host health checks
- Agent vs. agentless

**Mail gateway**

      A mail gateway is a server that examines and incoming and outgoing email and attempts to reduce associated risks.
      Located between the email server and the Internet. Common in UTMs.

- Spam filter

      Filters spam.

- DLP

      Examines outgoing email for sensitive information and blocks it if it contains any. Uses keywords and looks for those
      keywords in emails. Can be set to notify security professionals, the sender, or both whenever an email is blocked.

- Encryption

      Encrypts outgoing mail to ensure confidentiality for data-in-transit. Can also choose to only encrypt certain emails
      based on policies (Ex: all emails to a certain organization are encrypted). Encryption method varies between vendors 
      (certificate-based, password-based encryption).

**Bridge**

      Connects multiple networks together. Can be used instead of a router in some situations. Diverts traffic based on the
      destination MAC address. 

**SSL/TLS accelerators**

      SSL/TLS accelerators are hardware devices that focus on handling TCP traffic. TLS provides encryption for secure protcols like
      HTTPS. The process of creating encryptped traffic takes a lot of resources, making off-loading the processes to SSL/TLS accelerators
      an efficient option. It is best to place these accelerators near its related devices (Ex: next to a web server when off-loading TLS encryption
      for that web server).

**SSL decryptors**

      Encrypted malware can't be detected by IDSs. SSL decryptiors are placed in the DMZ and have traffic redirected to it. Unencrypted
      traffic passes with no issue, however encrypted traffic promts the SSL decryptor to create a separate SSL or TLS session between the
      traffic and the web site it originated from. This allows the SSL decryptor to view the unencrypted traffic to determine if it is malicious.
      Often used in NIPS because it has to be inline.

**Media gateway**

      Converts data from the format used on one network to the data format used on another network. Ex: VoIP gateway
      can convert telephony traffic to an IP-based network. Users can make phone calls using VoIP equipment, in which 
      the gateway can translate the traffic and transmit it over a traditional phone-line.

**Hardware security module**


### 2.2 Given a scenario, use appropriate software tools to assess the security posture of an organization.

**Protocol analyzer**

**Network scanners**

- Rogue system detection
- Network mapping

**Wireless scanners/cracker**

**Password cracker**

**Vulnerability scanner**

**Configuration compliance scanner**

**Exploitation frameworks**

**Data sanitization tools**

**Steganography tools**

**Honeypot**

      Diverts attackers from a live network by enticing them with an attractive, but ultimately useless, server. Enables
      observation of the attacke to learn about attacker methodologies or even zero-day attacks.

**Backup utilities**

**Banner grabbing**

**Passive vs. active**

**Command line tools**

- ping

      used to test connectivity to remote systems and verify domain name resolution. Can be used to test security posture
      by verifying that routers, firewalls, IPSs clock ICMP traffic when configured to do so. 

- netstat

      Shows TCP/IP statistics for a system. Allows you to view active TCP connections

- tracert

      Lists the routers between two systems. Each router is referred to as a hop. Tracert identifies the IP addresses, sometimes the host name
      of the hop, and the RTT (round trip time) for each hop. Tracert can help identify faulty routers and modified paths.
   
- nslookup/dig

      nslookup is used to troubleshoot DNS problems. It can verify that DNS servers can resolve specific host names to IP addresses. dig
      replaces nslookup on Linux. AKA domain information groper. dig verifies DNS by quering DNS, veryifying that the records exist, and
      verifying that the DNS server responds.

- arp

      Command related to ARP but is not the same thing. ARP resolves IP addresses to MAC addresses and stores the results in the ARP cache. The
      arp command is used to view and manipulate the ARP cache. 

- ipconfig/ip/ifconfig

      Shows TCP/IP information for a system. Includes the IP address, subnet mask, default gateway, MAC address, and the address of the DNS
      server. Also shows config info for NICs on a system. ifconfig allows the users to also configure NICs such as enabling promiscuous mode.

- tcpdump
- nmap
- netcat

### 2.3 Given a scenario, troubleshoot common security issues.

**Unencrypted credentials/clear text**

**Logs and events anomalies**

**Permission issues**

**Access violations**

**Certificate issues**

**Data exfiltration**

**Misconfigured devices**

- Firewall
- Content filter
- Access points

**Weak security configurations**

**Personnel issues**

- Policy violation
- Insider threat
- Social engineering
- Social media
- Personal email

**Unauthorized software**

**Baseline deviation**

**License compliance violation (availability/integrity)**

**Asset management**

**Authentication issues**

### 2.4 Given a scenario, analyze and interpret output from security technologies.

**HIDS/HIPS**

      Host-based Intrusion Detection System: additional software installed on a workstation or server. Monitors
      traffic that passes through its NIC, detecting attacks on that system. Can detect malicious missed by anti-virus.
      In contrast to NIDS, HIDS monitors only a signle host.
      
      Host-based Intrusion Prevention System: 

**Antivirus**

**File integrity check**

**Host-based firewall**

**Application allow list**

**Removable media control**

**Advanced malware tools**

**Patch management tools**

**UTM**

      Unified threat management is a single solution that combines multiple security controls (firewall, anti-spam, content filtering, etc.).
      Meant to increase security while simplifying management. Ex: can provide URL filtering, malware inspection, content inspection, and DDoS mitigation.

**DLP**

**Data execution prevention**

**Web application firewall**

      Firewall designed to protect a web application that is commonly hosted on a web server. Located between a server 
      hosting a web application and a client. Does not replace a network firewall, is meant for additional security.


### 2.5 Given a scenario, deploy mobile devices securely.

**Connection methods**

- Cellular
- WiFi
- SATCOM
- Bluetooth
- NFC
- ANT
- Infrared
- USB

**Mobile device management concepts**

- Application management
- Content management
- Remote wipe
- Geofencing
- Geolocation
- Screen locks
- Push notification services
- Passwords and pins
- Biometrics
- Context-aware authentication
- Containerization
- Storage segmentation
- Full device encryption

**Enforcement and monitoring for:**

- Third-party app stores
- Rooting/jailbreaking
- Sideloading
- Custom firmware
- Carrier unlocking
- Firmware OTA updates
- Camera use
- SMS/MMS
- External media
- USB OTG
- Recording microphone
- GPS tagging
- WiFi direct/ad hoc
- Tethering
- Payment methods

**Deployment models**

- BYOD
- COPE
- CYOD
- Corporate-owned
- VDI

### 2.6 Given a scenario, implement secure protocols.

**Protocols**

- DNSSEC

      Domain Name System Security Extensions. Prevents DNS poisoning by using digital signatures to validate DNS responses. DNS can
      confirm the integrity of data if it receives a DNSSEC enabled response that has digital signatures.

- SSH

      TCP 22. Secure shell. Used to encrypt traffic in transit. Can be used to encrypt other protocols such as FTP. Used as a replacement
      for Telnet because Telnet doesn't encrypt traffic for remote administration. SCP (Secure Copy) is based on SSH and is used to copy
      encrypted files over a network. 

- S/MIME
- SRTP

      Secure Real-time Transport Protocol. RTP delivers voice and video over IP networks. Includes VoIP, media streaming, etc.
      SRTP provides encryption, message authentication, and integrity for RTP. Protects against replay attacks.

- LDAPS

      LDAP uses TCP 389. It is used to communicate with directories like AD.
      LDAPS encrypts data using TLS and uses port 636

- FTPS
   
      File Transfer Protocol Secure. Extension of FTP that uses TLS to encrypt FTP traffic. Some implmentations use TCP 989 and 990.
      Can also encrypt FTP traffic on TCP 20 and 21.
  
- SFTP

      TCP 22. Secure FTP is also based on SSH and is used to transmit files in an encrypted format. Used to encrypt many different protocols.

- SNMPv3

      Simple Network Management Protocol V3.

- SSL/TLS

      Secure Sockets Layer/Transport Layer Security. SSL has a vulnerability that was not patched. TLS is strictly better.

- HTTPS

      HTTP: Hypertext Transfer Protocol. TCP 80. Transmits web traffic on the Internet. Uses HTML to display webpages.
      HTTPS: TCP 443. Encrypts web traffic to be secure while in transit. Indicated by a lock icon. Uses SSL or TLS. 

- Secure POP/IMAP

      POP3 (Post Office Protocol V3) transfers emails from servers to clients over TCP 110. Secure POP encrypts POP3 with SSL
      or TLS and can use TCP 995. However, it is recommended to use STARTTLS to create a secure connecion on TCP 110.
      IMAP4 (Internet Message Acess Protocol V4) stores emails on email servers. Allows users to organize and manage folders on
      the email server (Ex: Goodle Mail). Uses TCP 143. Secure IMAP encrypts with SSL or TLS and can use TCP 993, but it is
      recommended to use STARTTLS to use TCP 143.
      STARTTLS allows encrypted versions of protocols to use the same port as the unencrypted version.

**Use cases**

- Voice and video
- Time synchronization

      Sometimes systems need to be using the same time. Ex: Kerberos requires systems to be synchronized and within 5 minutes of each other.
      NTP (Network Time Protocol) causes all members of a domain to synchronize with their domain controller. SNPT (Simple NTP) doesn't use
      complex algorithms and is less accurate.

- Email and web
- File transfer
- Directory services
- Remote access

      Make changes from a desk computer instead of from a server room. SSH, RDP (Remote Desktop Protocol) TCP or UDP 3389, and VPNs
      support remote access.

- Domain name resolution

      UDP and TCP 53. DNS's primary use is to resolve domain names to IP addresses. Data is hosted in zones, which are like databases.
      These zones include records such as:
      - A: host record. Holds the host name and IPv4 address
      - AAAA: host record. Holds the host name and TPv6 address.

- Routing and switching
- Network address allocation

      Private networks are only allowed to have private IP ranges. These are defined in RFC 1918:
      10.x.y.z
      1712.16.y.z - 172.32.y.z
      192.168.y.z

      IPv6 uses unique local addresses instead of private IP addresses

- Subscription services

      Refers to subscription based business models. Common to use HTPPS connections for security. SMTP is used to send automated
      emails to notify of subscription endings.

# 3.0 Architecture and Design

### 3.1 Explain use cases and purpose for frameworks, best practices and secure configuration guides.

**Industry-standard frameworks and reference architectures**

- Regulatory
- Non-regulatory
- National vs. international
- Industry-specific frameworks

**Benchmarks/secure configuration guides**

- Platform/vendor-specific guides
   - Web server
   - Operating system
   - Application server
   - Network infrastructure devices
- General purpose guides

**Defense-in-depth/layered security**

- Vendor diversity
- Control diversity
   - Administrative
   - Technical
- User training

### 3.2 Given a scenario, implement secure network architecture concepts.

**Zones/topologies**

- Screened subnet (previously known as demilitarized zone)

      DMZ. Buffer zone between a private network and the Internet. Allows access to services inside the DMZ by Internet clients
      and provides additional protection for the Intranet. Commonly uses two firewalls.

- Extranet

      Part of a network that is accessible by authorized entities outside of the network. 

- Intranet

      Internal network. Used to share and communicated with each other internally.

- Wireless

      Provide a bridge to a wireless network, granting user access to all network resources as if they were on a wired PC.

- Guest

      Wireless network used to provide guests limited network access. Rarely gives network access and gives a way for
      guest to access web sites or check emails.
   
- Honeynets

      Group of honeypots in a separate network or zone. Often created with mutiple virtual servers on a single physical server.

- NAT

      Network Address Translation. Protocol that translates public IP addresses to private and private back to public.
      PAT (Port Address Translation) is a common use of NAT. NAT makes it so that public IP addresses don't need to be
      purchased for all clients and also hides private IP addresses from the Internet.
      Can be either static or dynamic.
      - Static NAT maps private IPs with public IPs in a one-to-one ratio.
      - Dynamic NAT maps multiple public IPs in a one-to-many mapping. Public IPs are mapped by load, making each request use
      - a less-used public IP address.

- Ad hoc

      Latin for "as needed." Wireless devices connect to each other without an AP (Ex: ad hoc network to connect two laptops wirelessly).
      Ad hoc networks are created as needed.

**Segregation/segmentation/isolation**

- Physical

      Physical isolation ensures that networks are not connected to other networks. Physically isolated networks are more secure
      because they can't be attacked form the Internet.

- Logical (VLAN)

      Logical separation is done through VLANS. Traffic is segmented between logical groups without regard to their physical location.
      Can also be used to separate traffic types, such as voice traffic on one VLAN and data traffic on a different VLAN.

- Virtualization
- Air gaps

      Metaphor for physical isolation. Air-gapped systems are not connected to any other systems.

**Tunneling/VPN**

- Site-to-site
- Remote access

**Security device/technology placement**

- Sensors
- Collectors
- Correlation engines
- Filters
- Proxies
- Firewalls

      Filters incoming and outgoing traffic.

- VPN concentrators
- SSL accelerators
- Load balancers
- DDoS mitigator
- Aggregation switches

      Aggregation switches connect multiple switches together in a network. It lowers the number of ports used by aggregating switches.
      Commonly placed in the same location as a router.

- Taps and port mirror

**SDN**

      Software Defined Networ. Uses virtualization to route traffic instead of routers and switches. Separates the logic used to forward or
      block traffic and the logic used to identify the path to take (data plane and control pane). Uses ABAC to allow administrators to create
      data plane polices to route traffic instead of ACLsfor traditional hardware.

### 3.3 Given a scenario, implement secure systems design.

**Hardware/firmware security**

- FDE/SED
- TPM
- HSM
- UEFI/BIOS
- Secure boot and attestation
- Supply chain
- Hardware root of trust
- EMI/EMP

**Operating systems**

- Types
   - Network
   - Server
   - Workstation
   - Appliance
   - Kiosk
   - Mobile OS
- Patch management
- Disabling unnecessary ports and services
- Least functionality
- Secure configurations
- Trusted operating system
- Application allow list/deny list
- Disable default accounts/passwords

**Peripherals**

- Wireless keyboards
- Wireless mice
- Displays
- WiFi-enabled MicroSD cards
- Printers/MFDs
- External storage devices
- Digital cameras


### 3.4 Explain the importance of secure staging deployment concepts.

**Sandboxing**

**Environment**

- Development
- Test
- Staging
- Production

**Secure baseline**

**Integrity measurement**


### 3.5 Explain the security implications of embedded systems.

**SCADA/ICS**

**Smart devices/IoT**

- Wearable technology
- Home automation

**HVAC**

**SoC**

**RTOS**

**Printers/MFDs**

**Camera systems**

**Special purpose**

- Medical devices
- Vehicles
- Aircraft/UAV

### 3.6 Summarize secure application development and deployment concepts.

**Development life-cycle models**

- Waterfall vs. Agile

**Secure DevOps**

- Security automation
- Continuous integration
- Baselining
- Immutable systems
- Infrastructure as code

**Version control and change management**

**Provisioning and deprovisioning**

**Secure coding techniques**

- Proper error handling
- Proper input validation
- Normalization
- Stored procedures
- Code signing
- Encryption
- Obfuscation/camouflage
- Code reuse/dead code
- Server-side vs. client-side execution and validation
- Memory management
- Use of third-party libraries and SDKs
- Data exposure

**Code quality and testing**

- Static code analyzers
- Dynamic analysis (e.g., fuzzing)
- Stress testing
- Sandboxing
- Model verification

**Compiled vs. runtime code**


### 3.7 Summarize cloud and virtualization concepts.

**Hypervisor**

      A hypervisor is the software that creates, manages, and runs VMs. (VMware)
      - Host: The physical system hosting the VMs. Requires more resources than a typical system to be effective.
      - Guest: Operating systems that run on the host system.
      - Host elasticity and scalability: Ability to resize host capacity based on load.
      
      Virtualization provides the best ROI when an organization has underutilized servers.

- Type I

      Run directly on the system hardware. AKA bare-metal hypervisor. Does not need to run within an operating system.

- Type II

      Run as a software on the host system.

- Application cells/containers

      AKA container virtualization. Runs services and applications in isolated application cells (containers). Apps cannot interact
      outside of their container. Uses fewer resources, making it more efficient than Type II hypervisors. However, containers must use the
      host operating system because they do not have their own kernel.

**VM sprawl avoidance**

      VM sprawl occurs when an organization has many VMs that are not managed properly. Unauthorized VMs are liable to security vulnerabilities
      as administrators may fail to locate and update them with the newest security patches. VMs also increase load onto a server, consuming resources
      especially when VMs are mismanaged.

**VM escape protection**

      VM escape is an attack that allows the attacker to access the host system from within the VM. Attackers may be able to run code on the VM that 
      enables them to interact with the hypervisor. Since many VMs are run with administrator privileges, VM escape can give an attacker unlimited control. 

**Cloud storage**

**Cloud deployment models**

- SaaS
- PaaS
- IaaS
- Private
- Public
- Hybrid
- Community

**On-premise vs. hosted vs. cloud**

**VDI/VDE**

      Virtual desktop interface/virtual desktop environment allow a user to run a desktop interface that runs as a VM on the server.
      This lowers hardware resource requirements as users can connect to a server over a network and run the desktop operating system
      from that server.
      Can be persistent or non-persistent. Persistent virtual desktops allow users to have custom desktop images, but increases disk use.
      Non-persistent virtual desktops provide all users with a preconfigured snapshot of a desktop that reverts to the original state after
      the user logs off.

**Cloud access security broker**

**Security as a service**


### 3.8 Explain how resiliency and automation strategies reduce risk.

**Automation/scripting**

- Automated courses of action
- Continuous monitoring
- Configuration validation

**Templates**

**Master image**

**Non-persistence**

- Snapshots

      Snapshots provide a copy of the VM at a moment in time. The hypervisor takes note of all changes that occur after the snapshot, and
      can revert back to the snapshot version of the VM whenever needed. Snapshots are usually taken before risky operations because it allows
      administrators to easily roll back the system to a known good state with a known good configuration.

- Revert to known state
- Rollback to known configuration
- Live boot media

**Elasticity**

**Scalability**

**Distributive allocation**

**Redundancy**

**Fault tolerance**

**High availability**

**RAID**

### 3.9 Explain the importance of physical security controls.

**Lighting**

**Signs**

**Fencing/gate/cage**

**Security guards**

**Alarms**

**Safe**

**Secure cabinets/enclosures**

**Protected distribution/Protected cabling**

**Airgap**

**Access control vestibule**

**Faraday cage**

**Lock types**

**Biometrics**

**Barricades/bollards**

**Tokens/cards**

**Environmental controls**

- HVAC
- Hot and cold aisles
- Fire suppression

**Cable locks**

**Screen filters**

**Cameras**

**Motion detection**

**Logs**

**Infrared detection**

**Key management**


# 4.0 Identity and Access Management

### 4.1 Compare and contrast identity and access management concepts

**Identification, authentication, authorization and accounting (AAA)**

      Identification: claiming an identity such as a username or email address
      Authentication: proving the claimed identity (i.e. password)
      Authorization: granting access based on permissions granted to the proven identity
      Accounting: tracking and recording user activity in logs to create an audit trail

**Multifactor authentication**

- Something you are

      Biometric identification (i.e. fingerprint, retina scan)
      Biometric ID can sometimes be incorrect.
      - FAR: False acceptance rate. Identifies percentage of times in which a biometric system incorrectly 
             identifies an unauthorized user as an authorized user.
      - FRR: False rejection rate. Identifies percentage of times in which a biometric system incorrectly
             rejects an authorized user.
      - CER: Crossover error rate. The point at which FAR = FRR. (Think supply-demand graph)

- Something you have

      USB tokens
      Smart cards: made up of an embedded certificate and uses PKI. The embedded certificate contains the user's private key
                   and is matched with the public key. 
      - CAC: Common Access Card. Special smart card used by the U.S. Department of Defense. Includes photo ID.
      - PIV: Personal Identity Verification: Special smart card used by U.S. Federal Entities. Includes photo ID.

- Something you know

      Passwords and PINs

- Somewhere you are

      Geofencing, GPS location

- Something you do

      Signatures, gestures on a touch screen

**Federation**

**Single sign-on**

      Ability to log into multiple systems by providing credentials once. Primary purpose is identification and authentication. 
      Does not provide authorization.

**Transitive trust**

      A trusts B. B trusts C. A trusts C through transitive trust.


### 4.2 Given a scenario, install and configure identity and access services.

**LDAP**

      Lightweight Directory Access Protocol
      Has SSO capabilities. Transmissions are encrypted with TLS.
      LDAP specifies formats and methods to query directories. Protocols to read/write
      directories ofver an IP network. Functions similarly to a phone directory.
      Uses TCP/IP (TCP/389 and UDP/389
      LDAP database stores information as attributes and fields (attribute=field, Ex: LDAP://CN=WidgetWeb,CN=Users,DC=GCGA,DC=com)
      - CN = Common Name
      LDAPS encrypts transmissions with SSL or TLS
      
**Kerberos**

      Kerberos is a network authentication protocol used in Windows Active Directory domains or in Unix realms that has SSO capabilities.
      It provides mutual authentication by using a KDC to issue TGTs. These tickets provide authentification for users
      when they access resources such as files on a file server
      It also uses time synchronization, requiring systems to be synchronized within 5 minutes of each other (Kerberos V5). Tickets are
      are also timestamped and expire accordingly. This prevents replay attacks since the attacker has a limited time to use the ticket.
      
      
**TACACS+**

**CHAP**

**PAP**

**MSCHAP**

**RADIUS**

**SAML**

      Security Assertion Markup Language
      Provides federation purposes (SSO) for web-based applications. XML based standard.
      Three roles:
      - Principal: user
      - Identity provider: IdP. Creates, maintains, and manages identity information for principals
      - Service provider: Entity that provides services to principals. 

**OpenID Connect**

      Works with OAUTH 2.0 to verify end user identity without managing their credentials. Provides identification
      services and can also personalize user experience.

**OAUTH**

      Open standard that streamlines authorization. Use previous secure account to access protected resources. (Ex: using a
      Goggle account to make a Minecraft account)

**Shibboleth**

      Open source federated identity solution. Includes Open SAML libraries.

**Secure token**

      Tokens AKA key fobs are small electronic devices that have an LCD that displays a number that changes periodically (Ex: 60 s).
      Tokens are synced with servers, creating a TOTP. 

**NTLM**

      New technology LAN Manager is a suite of protocols that provide authentication, integrity, and confidentiality in Windows systems.
      Windows only
      NTLM has three versions which are all not recommended for usage. Most have upgraded to Kerberors but still
      support NTLM for backwards compatibility.
      - NTLM: MD4 hash of password. MD4 has been cracked
      - NTLMv2: Challenge response authentication protocol. Uses HMAC-MD5 hash of username, password, domainname, time
      - NTLM2 Session: adds mutual authentication to NTLMv2


### 4.3 Given a scenario, implement identity and access management controls.

**Access control models**

- MAC

      Mandatory access control. Assigns sensitivity labels to subjects and object. When labels match, access is granted. Ex: Users with
      Top Secret labels can access Top Secret files. Access can also be restricted on a need-to-know basis, meaning that
      anyone with a Top Secret label can't access all Top Secret files. SELinux (security Enhanced Linux) uses MAC.
      MAC model lattice divides access into several compartments based on a need-to-know.
      
- DAC

      Discretionary access control. Every object (files and folders) have an owner. That owner establishes access for the object.
      NTFS uses DAC.

- ABAC

      Attribute Based Access Control evaluates attributes and grants access based on the value of those attributes. (Ex: employer,
      inspector, nuclear aware). 
      Many SDNs use ABAC models. Instead of rules, policy statements are used to grant access. They consist of:
      - Subject: The user
      - Object: What the user is trying to access
      - Action: What the user is trying to do
      - Environment: Everything outside of subject and object attributes/the context of the access request. Includes: time, location,
                     protocol, encryption, devices, and communication method.
      ABAC can function similarly to DAC and MAC. In ABAC, owners can create policies to grant access and attributes function
      as labels that match users with objects.

- Role-based access control

      Roles are assigned different privileges. A matrix is a planning document that matches roles with the required privileges.
      Roles can consist of groups. Administrators can assign users to groups and assign privileges to the group.

- Rule-based access control

      Uses rules to control access. ACL are firewall rules that define what traffic is permitted. Rules can be dynamic, detecting
      attacks and modifying rules or granting additional privileges to a user.
      Mainly used for routers, firewalls, and advanced implementations can be used for applications.

**Physical access control**

- Proximity cards
- Smart cards

**Biometric factors**

- Fingerprint scanner
- Retinal scanner
- Iris scanner
- Voice recognition
- Facial recognition
- False acceptance rate
- False rejection rate
- Crossover error rate

**Tokens**

- Hardware
- Software
- HOTP/TOTP

**Certificate-based authentication**

- PIV/CAC/smart card
- IEEE 802.1x

      Port-based authentication protocol. Requires users or devices to authenticate when connecting to a specific wireless access
      point or a specific physical port. Can use username-password authentication or certificate-based authentication.
      Prevents rouge devices from connecting.

**File system security**

**Database security**


### 4.4 Given a scenario, differentiate common account management practices.

**Account types**

- User account

      Regular end user account. Assigned privileges based on responsibilities.

- Shared and generic accounts/credentials

      Account management key concepts are identification, authentication, authorization, and accounting. Shared accounts
      prevent logs from identifying exactly who used that account, preventing accounting. Should be disabled for security
      purposes.

- Guest accounts

      Account that has limited access. Good for temporary employess. Often disabled and only enabled when needed.

- Service accounts

      Applications and servers that need to run under the context of an account. Ex: SQL Server is a database application
      that requires access to resources on the server and the network. Administrators configure a standard user account with
      the required privileges. Only the server or application will then use this service account.
      Often unmanaged, so they should be configured to not have to comply with password expiration policies to prevent lockout.

- Privileged accounts

      Additional privileges than a user account. Ex: Windows Administrator account. Administrators should use two accounts: administrator
      for only administration purposes and a user account for everything else. This prevents time spent on the administrator account,
      making it more difficult for attackers to access.

**General Concepts**

- Least privilege
- Onboarding/offboarding
- Permission auditing and review
- Usage auditing and review
- Time-of-day restrictions

      Specifies what time users can log into a computer. Can be assigned to each user. For overtime purposes, doesnt log user
      off when time limit is reached, but prevents making new network connections.
      Network wise, can restrict access based on computer names or MAC addresses. Can make it so that log on is only possible
      through one computer.

- Recertification
- Standard naming convention
- Account maintenance
- Group-based access control
- Location-based policies

      Restrict access based on the location of the user. Geolocation can restrict based on IP addresses, either by blocking
      foreign IP addresses or whitelisting. 

**Account policy enforcement**

- Credential management

      A credential is a system of information that provides an identiy and proves that identity (Ex: username and password).
      Credential management systems store credentials securely. 

- Group policy

      Group Policy allows administrators to configure settings in a Group Policy object and apply settings the multiple
      users in the domain. Implemented on a domain controller to easily make changes in the domain. Group Policy is often
      used to create password policies, implement security settings, configure host-based firewalls, etc.

- Password complexity

      Good complex passwords combine at least 3 out of 4 types: uppercase characters, lowercase characters, numbers, 
      and special characters.
      Jan 2016, recommended password length is at least 14 characters.
      Passwords that are too complex are less secure since they are more likely to be written down.

- Expiration

      Password becomes unusable after a set amount of time (Ex: 45-90 days). Forces users to change passwords.
      Good for temporary contractual workers.

- Recovery
   
      Identity must be verified before a password is reset. The administrator should provide a temporary password
      tha the user changes later to make sure that only one person knows the password.
      Disabled accounts can be reenabled and deleted accounts can be recovered. The latter is much more complex.

- Disablement

      Deleting an account destroys encryption and security keys related to that account. May cause some files to remain
      encrypted. As such, it is better to disable accounts rather than delete them so that data remains available.
      Disablement policies can include: disable account when employee is terminated, disable account during leave of absence,
                                        and delete account after some period of time and if it is determined the account is no longer needed.

- Lockout

      Lockout policies prevents users from guessing passwords.
      - Account lockout threshold: maximum # of times a wrong password can be entered. System locks the account when
                                   threshold is reached
      - Account lockout duration: How long the account remains locked. Duration of 0 is indefinite and requires
                                  an administrator to unlock the account.

- Password history

      Password history system remembers past passwords and prevents their reuse. Common to remember the last 24 passwords.

- Password reuse

      Passwords should not be reused. Common to remember the last 24 passwords.

- Password length

      14 characters minimum is standard.


# 5.0 Risk Management

### 5.1 Explain the importance of policies, plans and procedures related to organizational security.

**Standard operating procedure**

**Agreement types**

- BPA
- SLA
- ISA
- MOU/MOA

**Personnel management**

- Mandatory vacations
- Job rotation
- Separation of duties
- Clean desk
- Background checks
- Exit interviews
- Role-based awareness training
   - Data owner
   - Systems administrator
   - System owner
   - User
   - Privileged user
   - Executive user
- NDA
- Onboarding
- Continuing education
- Acceptable use policy/rules of behavior
- Adverse actions

**General security policies**

- Social media networks/applications
- Personal email

### 5.2 Summarize business impact analysis concepts.

**RTO/RPO**

**MTBF**

**MTTR**

**Mission-essential functions**

**Identification of critical systems**

**Single point of failure**

**Impact**

- Life
- Property
- Safety
- Finance
- Reputation

**Privacy impact assessment**

**Privacy threshold assessment**


### 5.3 Explain risk management processes and concepts.

**Threat assessment**

- Environmental
- Artificial/manufactured
- Internal vs. external

**Risk assessment**

- SLE
- ALE
- ARO
- Asset value
- Risk register
- Likelihood of occurrence
- Supply chain assessment
- Impact
- Quantitative
- Qualitative
- Testing
   - Penetration testing authorization
   - Vulnerability testing authorization

- Risk response techniques
   - Accept
   - Transfer
   - Avoid
   - Mitigate

**Change management**



### 5.4 Given a scenario, follow incident response procedures.

**Incident response plan**

- Documented incident types/category definitions
- Roles and responsibilities
- Reporting requirements/escalation
- Cyber-incident response teams
- Exercise

**Incident response process**

- Preparation
- Identification
- Containment
- Eradication
- Recovery
- Lessons learned

### 5.5 Summarize basic concepts of forensics.

**Order of volatility**

**Chain of custody**

**Legal hold**

**Data acquisition**

- Capture system image
- Network traffic and logs
- Capture video
- Record time offset
- Take hashes
- Screenshots
- Witness interviews

**Preservation**

**Recovery**

**Strategic intelligence/counterintelligence gathering**

- Active logging

**Track person hours**

### 5.6 Explain disaster recovery and continuity of operations concepts.

**Recovery sites**

- Hot site
- Warm site
- Cold site

**Order of restoration**

**Backup concepts**

- Differential
- Incremental
- Snapshots
- Full

**Geographic considerations**

- Off-site backups
- Distance
- Location selection
- Legal implications
- Data sovereignty

**Continuity of operations planning**

- Exercises/tabletop
- After-action reports
- Failover
- Alternate processing sites
- Alternate business practices

### 5.7 Compare and contrast various types of controls.

      Technical, administrative, and physical describe the types of controls. Deterrent, preventive, detective, corrective,
      and compensating describe the goal of the control.

**Deterrent**

      Discourage threats
      Ex: cable locks, hardware locks

**Preventive**

      Prevent security incidents from occuring in the first place.
      Ex: 
      - Hardening: making a system more secure than its default configuration. Done through layered security (disabling unnecessary
                   ports and services, implementing secure protocols, strong password policies, and disabling unnecessary accounts)
      - Security awareness and training: ensures that users are aware of vulnerabilities and social engineering techniques.
      - Security guards: Verifies identities to prevent unauthorized access. Can also serve as a detterent.
      - Change management: makes administrators unable to make changes on the fly. Is an operational control that serves as a preventative control.
      - Account disablement policy: disable ex-employee user accounts to prevent unauthorized access.

**Detective**

      Detect when vulnerabilities have been exploited.
      Ex:
      - Log monitoring: logs record details of activity on systems and networks.
      - Trend analysis: can analyze trends to detect increase in attacks on a specific system.
      - Security audit: determine the security posture of an organization
      - Video surveillance: CCTV can detect physical activity
      - Motion detection: detects movement
      
**Corrective**

      Attempt to reverse the impact of a security incident.
      Ex:
      - IPS: can detect attacks and modify 
      - Backups: allow for systesm to be recovered

**Compensating**

      Compensation controls are alternative controls used when the primary control is unavailable. 
      Ex: Smart card policy enacted but not issued to employees yet. TOTP used to maintain temporary security.

**Technical**

      Uses technology to reduce vulnerabilities. After an administrator installs a technical control, the technical
      controll will provide protection automatically.
      Ex: Encryption, antivirus, IDs and IPS, firewalls, least privilege principles, motion detectors, fire suppression systems.

**Administrative**

      Uses methods that are mandated by organizational policies.
      Ex: risk assesssments, vulnerability assessments, penetration tests.
      AKA operational/management controls because they ensure that day-to-day operations comply with security plans.
      Ex: Awareness and training, configuration and change management, contingency planning

**Physical**

      Physical controls are controls that can be physcially touched. 
      Ex: lighting, signs, fences, security guards

### 5.8 Given a scenario, carry out data security and privacy practices.

**Data destruction and media sanitization**

- Burning
- Shredding
- Pulping
- Pulverizing
- Degaussing
- Purging
- Wiping

**Data sensitivity labeling and handling**

- Confidential
- Private
- Public
- Proprietary
- PII
- PHI

**Data roles**

- Owner
- Steward/custodian
- Privacy officer

**Data retention**

**Legal and compliance**


# 6.0 Cryptography and PKI

### 6.1 Compare and contrast basic concepts of cryptography.

**Symmetric algorithms**

**Modes of operation**

**Asymmetric algorithms**

**Hashing**

**Salt, IV, nonce**

**Elliptic curve**

**Weak/deprecated algorithms**

**Key exchange**

**Digital signatures**

**Diffusion**

**Confusion**

**Collision**

**Steganography**

**Obfuscation**

**Stream vs. block**

**Key strength**

**Session keys**

**Ephemeral key**

**Secret algorithm**

**Data-in-transit**

      Data-in-transit is any traffic sent over a network. Protocol analyzers can capture data sent in cleartext and read it. 

**Data-at-rest**

**Data-in-use**

**Random/pseudo-random number generation**

**Key stretching**

**Implementation vs. algorithm selection**

- Crypto service provider
- Crypto modules

**Perfect forward secrecy**

**Security through obscurity**

**Common use cases**
      
      A use case is essentially a goal. Usually takes a verb-noun format as in "Place Order."

- Low power devices
- Low latency
- High resiliency

      AKA high availability. Indicates that services are available when needed. 
      Accomplished through redundancy which increases fault tolerance.
      Focuses on removing SPOF or Single point of failure. Goal of redundancy is to remove SPOF because that failure can 
      cause the entire system to fail.
      Ways to increase fault tolerance:
      - Disk redundancies: RAID-1 (mirroring), RAID-5 (striping with parity) allow system to operate even if a disk fails.
      - Server redundancies: failover clusters include redundant servers that take over when a server fails.
      - Load balancing: the usage of multiple servers to support a single service
      - Site redundancies: backup infrastructure sites in case of natural disasters.
           - Hot site: ready and available 24/7. Mirrors the infrastructure of the original site.
           - Cold site: only contains the area . Nothing is up and running
           - Warm site: mix between hot and cold
      - Alternate power: UPSs - uninteruptible power supplies continue powering equipment
      - Cooling systems: HVAC prevents outages caused by overheating
      - Patching: ensures that bugs are minimized and keeps software up to date.

- Supporting confidentiality

      Confidentiality: prevents the unauthorized disclosure of data. Only allows data to be accessed by authorized personnel.
      Confidentiality is supported by:
      - Encryption: scrambles data making it humanly unreadable. Authorized personnel access encrypted data by decrypting it
      - Access Controls: Identification, authentication, and authorization provide access controls to ensure that only
                         authorized personell can access data.
           - Identification: Users claim unique indentities (i.e. user accounts with unique usernames)
           - Authentication: Users prove their identity with authentication (i.e. passwords)
           - Authorization: Restrict and enable user access. (i.e. group permissions in Windows)
      - Steganography and Obfuscation: Enables confidentiality by hiding data
           - Steganography: hides data within an image by modifying bits in the file (i.e. adding hidden text to image)
           - Obfuscation: making something unclear or difficult to understand. AKA security through obscurity.
                          Not a reliable form of security.

- Supporting integrity

      Integrity: provides assurance that the data has not been modified, tampered with, or corrupted.
      Data integrity can also be lost due to human error (i.e. faulty bulk update scripts).
      Ways to verify integrity:
      - Hashing: A hash is a number generated from the exection of a hashing algorithm. To determine integrity, hashes
                 can be created at the source and destination at two different times. Integrity can be determined
                 by running a hashing algorithm on a received message and comparing the generated hash with the hash
                 that was sent along with the received message. If both hashes are the same, the data was not modified.
                 EX: MD5, SHA-1, SHA-2, HMAC
      - Digital signatures: similar to a handwritten signature. Not easy to reproduce. Provides integrity, authentication, 
                            and non-repudiation. 
                            Uses keys to encrypt certificates and PKI to create, manage, and distribute certificates.
      
- Supporting obfuscation

      Obfuscation: making something unclear or difficult to understand. AKA security through obscurity.
                          Not a reliable form of security.

- Supporting authentication

      Users prove their identity by authenticating. Ex: password, ID

- Supporting non-repudiation

      No take backs. Senders can not deny having sent data. Digital signatures are often used to repudiate claims.

- Resource vs. security constraints

      Security must be balanced by the amount of available resources. Encrypted data takes up more disk space and encryption 
      and decription use up processing time and processing power. The goal is to minizmize costs w/out sacrificing security.

      


### 6.2 Explain cryptography algorithms and their basic characteristics.

**Symmetric algorithms**

- AES
- DES
- 3DES
- RC4
- Blowfish/Twofish

**Cipher modes**

- CBC
- GCM
- ECB
- CTR
- Stream vs. block

**Asymmetric algorithms**

- RSA
- DSA
- Diffie-Hellman
   - Groups
   - DHE
   - ECDHE
- Elliptic curve
- PGP/GPG

**Hashing algorithms**

- MD5
- SHA
- HMAC
- RIPEMD

**Key stretching algorithms**

- BCRYPT
- PBKDF2

**Obfuscation**

- XOR
- ROT13
- Substitution ciphers


### 6.3 Given a scenario, install and configure wireless security settings.

**Cryptographic protocols**

- WPA

      Wi-Fi Protected Access. Interim replacement for WEP until WPA2 was developed. Susceptible to password-cracking attacks.
      Uses TKIP, or AES as an upgrade.

- WPA2

      WPA replacement. AKA IEEE 802.11i. Needs to have the WI-FI CERTIFIED logo and use CCMP to meet WPA2 standards. The best
      cryptographic wireless protocol.

- CCMP

      Counter mode with Cipher block chaining Message Authentication Protocol. Stronger than TKIP.

- TKIP

      Temporal Key Integrity Protocol. Often used with legacy systems. Used with WPA. Has been cracked, so if upgrade to WPA2 is
      not possible, TKIP should be upgraded to use AES.

**Authentication protocols**

- EAP

      Extensible Authentication Protocol. Is an authentication framework that provides guidance for authentication methods.
      Provides a method for two computers to create a secure encryption key called a PMK (Pairwise Master Key). Not as secure as CCMP.

- PEAP

      Protected EAP. 

- EAP-FAST

      EAP-Flexible Authentication via Secure Tunneling. Designed by CISCO to be a secure replacement for Lightweight EAP. Supports
      optional certificates.

- EAP-TLS



- EAP-TTLS



- IEEE 802.1x
- RADIUS Federation

**Methods**

- PSK vs. Enterprise vs. Open
      
      WPA and WPA2 can operate in three modes: PSK, Enterprise, or Open
      PSK: Pre-Shared Key. Users access the wireless network anonymously using a PSK (password). Does not authenticate.
      Enterprise: Forces users to authenticate with unique credentials before gaining access to the wireless network. Uses 802.1x server,
      often implemented as RADIUS. 
      Open: no security. Allows everyone to access the AP.

- WPS
- Captive portals


### 6.4 Given a scenario, implement public key infrastructure.

**Components**

- CA
- Intermediate CA
- CRL
- OCSP
- CSR
- Certificate
- Public key
- Private key
- Object identifiers (OID)

**Concepts**

- Online vs. offline CA
- Stapling
- Pinning
- Trust model
- Key escrow
- Certificate chaining

**Types of certificates**

- Wildcard
- SAN
- Code signing
- Self-signed
- Machine/computer
- Email
- User
- Root
- Domain validation
- Extended validation

**Certificate formats**

- DER
- PEM
- PFX
- CER
- P12
- P7B


