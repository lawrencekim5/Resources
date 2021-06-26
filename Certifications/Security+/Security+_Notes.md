

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
- Application-based vs. network-based
- Stateful vs. stateless
- Implicit deny

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

- Signature-based
- Heuristic/behavioral
- Anomaly
- Inline vs. passive
- In-band vs. out-of-band
- Rules
- Analytics
   - False positive
   - False negative

**Router**

- ACLs
- Antispoofing

**Switch**

- Port security
- Layer 2 vs. Layer 3
- Loop prevention
- Flood guard

**Proxy**

- Forward and reverse proxy
- Transparent
- Application/multipurpose

**Load balancer**

- Scheduling
   - Affinity
   - Round-robin
- Active-passive
- Active-active
- Virtual IPs

**Access point**

- SSID
- MAC filtering
- Signal strength
- Band selection/width
- Antenna types and placement
- Fat vs. thin
- Controller-based vs. standalone

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

- Spam filter
- DLP
- Encryption

**Bridge**

**SSL/TLS accelerators**

**SSL decryptors**

**Media gateway**

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

**Backup utilities**

**Banner grabbing**

**Passive vs. active**

**Command line tools**

- ping
- netstat
- tracert
- nslookup/dig
- arp
- ipconfig/ip/ifconfig
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

**Antivirus**

**File integrity check**

**Host-based firewall**

**Application allow list**

**Removable media control**

**Advanced malware tools**

**Patch management tools**

**UTM**

**DLP**

**Data execution prevention**

**Web application firewall**


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
- SSH
- S/MIME
- SRTP
- LDAPS
- FTPS
- SFTP
- SNMPv3
- SSL/TLS
- HTTPS
- Secure POP/IMAP

**Use cases**

- Voice and video
- Time synchronization
- Email and web
- File transfer
- Directory services
- Remote access
- Domain name resolution
- Routing and switching
- Network address allocation
- Subscription services

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
- Extranet
- Intranet
- Wireless
- Guest
- Honeynets
- NAT
- Ad hoc

**Segregation/segmentation/isolation**

- Physical
- Logical (VLAN)
- Virtualization
- Air gaps

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
- VPN concentrators
- SSL accelerators
- Load balancers
- DDoS mitigator
- Aggregation switches
- Taps and port mirror

**SDN**

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

- Type I
- Type II
- Application cells/containers

**VM sprawl avoidance**

**VM escape protection**

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

**Multifactor authentication**

- Something you are
- Something you have
- Something you know
- Somewhere you are
- Something you do

**Federation**

**Single sign-on**

**Transitive trust**


### 4.2 Given a scenario, install and configure identity and access services.

**LDAP**

**Kerberos**

**TACACS+**

**CHAP**

**PAP**

**MSCHAP**

**RADIUS**

**SAML**

**OpenID Connect**

**OAUTH**

**Shibboleth**

**Secure token**

**NTLM**


### 4.3 Given a scenario, implement identity and access management controls.

**Access control models**

- MAC
- DAC
- ABAC
- Role-based access control
- Rule-based access control

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

**File system security**

**Database security**


### 4.4 Given a scenario, differentiate common account management practices.

**Account types**

- User account
- Shared and generic accounts/credentials
- Guest accounts
- Service accounts
- Privileged accounts

**General Concepts**

- Least privilege
- Onboarding/offboarding
- Permission auditing and review
- Usage auditing and review
- Time-of-day restrictions
- Recertification
- Standard naming convention
- Account maintenance
- Group-based access control
- Location-based policies

**Account policy enforcement**

- Credential management
- Group policy
- Password complexity
- Expiration
- Recovery
- Disablement
- Lockout
- Password history
- Password reuse
- Password length


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

### 5.2 Summarize basic concepts of forensics.

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

**Deterrent**

**Preventive**

**Detective**

**Corrective**

**Compensating**

**Technical**

**Administrative**

**Physical**


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

- Low power devices
- Low latency
- High resiliency
- Supporting confidentiality
- Supporting integrity
- Supporting obfuscation
- Supporting authentication
- Supporting non-repudiation
- Resource vs. security constraints


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
- WPA2
- CCMP
- TKIP

**Authentication protocols**

- EAP
- PEAP
- EAP-FAST
- EAP-TLS
- EAP-TTLS
- IEEE 802.1x
- RADIUS Federation

**Methods**

- PSK vs. Enterprise vs. Open
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



CompTIA Security+ Acronyms
The following is a list of acronyms that appear on the CompTIA Security+ exam.
Candidates are encouraged to review the complete list and attain a working
knowledge of all listed acronyms as part of a comprehensive exam preparation
program.


3DES
AAA
ABAC
ACL
AES
AES256
AH
ALE
AP
API
APT
ARO
ARP
ASLR
ASP
AUP
AV
AV
BAC
BCP
BIA
BIOS
BPA
BPDU
BYOD
CA
CAC
CAN
CAPTCHA

Triple Digital Encryption Standard
Authentication, Authorization, and Accounting
Attribute-based Access Control
Access Control List
Advanced Encryption Standard
Advanced Encryption Standards 256bit
Authentication Header
Annualized Loss Expectancy
Access Point
Application Programming Interface
Advanced Persistent Threat
Annualized Rate of Occurrence
Address Resolution Protocol
Address Space Layout Randomization
Application Service Provider
Acceptable Use Policy
Antivirus
Asset Value
Business Availability Center
Business Continuity Planning
Business Impact Analysis
Basic Input/Output System
Business Partners Agreement
Bridge Protocol Data Unit
Bring Your Own Device
Certificate Authority
Common Access Card
Controller Area Network
Completely Automated Public Turing
Test to Tell Computers and Humans Apart
Corrective Action Report
Cloud Access Security Broker
Cipher Block Chaining
Counter-Mode/CBC-Mac Protocol
Closed-circuit Television

CER
CER
CERT
CFB
CHAP
CIO
CIRT
CMS
COOP
COPE
CP
CRC
CRL
CSIRT
CSO
CSP
CSR
CSRF
CSU
CTM
CTO
CTR
CYOD
DAC
DBA
DDoS
DEP
DER
DES
DFIR
DHCP
DHE
DHE
DLL
DLP

Certificate
Cross-over Error Rate
Computer Emergency Response Team
Cipher Feedback
Challenge Handshake Authentication Protocol
Chief Information Officer
Computer Incident Response Team
Content Management System
Continuity of Operations Plan
Corporate Owned, Personally Enabled
Contingency Planning
Cyclical Redundancy Check
Certificate Revocation List
Computer Security Incident Response Team
Chief Security Officer
Cloud Service Provider
Certificate Signing Request
Cross-site Request Forgery
Channel Service Unit
Counter-Mode
Chief Technology Officer
Counter
Choose Your Own Device
Discretionary Access Control
Database Administrator
Distributed Denial of Service
Data Execution Prevention
Distinguished Encoding Rules
Digital Encryption Standard
Digital Forensics and Investigation Response
Dynamic Host Configuration Protocol
Data-Handling Electronics
Diffie-Hellman Ephemeral
Dynamic Link Library
Data Loss Prevention

CAR
CASB
CBC
CCMP
CCTV

CompTIA Security+ Certification Exam Objectives Version 7.0 (Exam Number: SY0-501)

ACRONYM

SPELLED OUT

ACRONYM

SPELLED OUT

DMZ
DNAT
DNS
DoS
DRP
DSA
DSL
DSU
EAP
ECB
ECC
ECDHE
ECDSA
EF
EFS
EMI
EMP
EOL
ERP
ESN
ESP
EULA
FACL
FAR
FDE
FRR
FTP
FTPS
GCM
GPG
GPO
GPS
GPU
GRE
HA
HDD
HIDS
HIPS
HMAC
HOTP
HSM
HTML
HTTP
HTTPS
HVAC

Demilitarized Zone
Destination Network Address Translation
Domain Name Service (Server)
Denial of Service
Disaster Recovery Plan
Digital Signature Algorithm
Digital Subscriber Line
Data Service Unit
Extensible Authentication Protocol
Electronic Code Book
Elliptic Curve Cryptography
Elliptic Curve Diffie-Hellman Ephemeral
Elliptic Curve Digital Signature Algorithm
Exposure Factor
Encrypted File System
Electromagnetic Interference
Electro Magnetic Pulse
End of Life
Enterprise Resource Planning
Electronic Serial Number
Encapsulated Security Payload
End User License Agreement
File System Access Control List
False Acceptance Rate
Full Disk Encryption
False Rejection Rate
File Transfer Protocol
FTP over SSL
Galois Counter Mode
Gnu Privacy Guard
Group Policy Object
Global Positioning System
Graphic Processing Unit
Generic Routing Encapsulation
High Availability
Hard Disk Drive
Host-based Intrusion Detection System
Host-based Intrusion Prevention System
Hashed Message Authentication Code
HMAC-based One-Time Password
Hardware Security Module
Hypertext Markup Language
Hypertext Transfer Protocol
Hypertext Transfer Protocol over SSL/TLS
Heating, Ventilation and Air Conditioning

IaaS
ICMP
ICS
ID
IDEA
IDF
IdP
IDS
IEEE
IIS
IKE
IM
IMAP4
IoT
IP
IPSec
IR
IR
IRC
IRP
ISA
ISP
ISSO
ITCP
IV
KDC
KEK
L2TP
LAN
LDAP
LEAP
MaaS
MAC
MAC
MAC
MAN
MBR
MD5
MDF
MDM
MFA
MFD
MIME
MMS
MOA

Infrastructure as a Service
Internet Control Message Protocol
Industrial Control Systems
Identification
International Data Encryption Algorithm
Intermediate Distribution Frame
Identity Provider
Intrusion Detection System
Institute of Electrical and Electronic Engineers
Internet Information System
Internet Key Exchange
Instant Messaging
Internet Message Access Protocol v4
Internet of Things
Internet Protocol
Internet Protocol Security
Incident Response
Infrared
Internet Relay Chat
Incident Response Plan
Interconnection Security Agreement
Internet Service Provider
Information Systems Security Officer
IT Contingency Plan
Initialization Vector
Key Distribution Center
Key Encryption Key
Layer 2 Tunneling Protocol
Local Area Network
Lightweight Directory Access Protocol
Lightweight Extensible Authentication Protocol
Monitoring as a Service
Mandatory Access Control
Media Access Control
Message Authentication Code
Metropolitan Area Network
Master Boot Record
Message Digest 5
Main Distribution Frame
Mobile Device Management
Multifactor Authentication
Multi-function Device
Multipurpose Internet Mail Exchange
Multimedia Message Service
Memorandum of Agreement

CompTIA Security+ Certification Exam Objectives Version 7.0 (Exam Number: SY0-501)

ACRONYM

SPELLED OUT

ACRONYM

SPELLED OUT

MOTD
MOU
MPLS
MSCHAP

Message of the Day
Memorandum of Understanding
Multi-Protocol Label Switching
Microsoft Challenge Handshake
Authentication Protocol
Managed Service Provider
Mean Time Between Failures
Mean Time to Failure
Mean Time to Recover or Mean Time to Repair
Maximum Transmission Unit
Network Access Control
Network Address Translation
Non-disclosure Agreement
Near Field Communication
Next Generation Access Control
Network-based Intrusion Detection System
Network-based Intrusion Prevention System
National Institute of Standards & Technology
New Technology File System
New Technology LAN Manager
Network Time Protocol
Open Authorization
Online Certificate Status Protocol
Object Identifier
Operating System
Over The Air
Open Vulnerability Assessment Language
PKCS #12
Peer to Peer
Platform as a Service
Proxy Auto Configuration
Pluggable Authentication Modules
Password Authentication Protocol
Port Address Translation
Password-based Key Derivation Function 2
Private Branch Exchange
Packet Capture
Protected Extensible Authentication Protocol
Personal Electronic Device
Privacy-enhanced Electronic Mail
Perfect Forward Secrecy
Personal Exchange Format
Pretty Good Privacy
Personal Health Information
Personally Identifiable Information
Personal Identity Verification

PKI
POODLE
POP
POTS
PPP
PPTP
PSK
PTZ
RA
RA
RAD
RADIUS
RAID
RAS
RAT
RBAC
RBAC
RC4
RDP
REST
RFID
RIPEMD

Public Key Infrastructure
Padding Oracle on Downgrade Legacy Encryption
Post Office Protocol
Plain Old Telephone Service
Point-to-Point Protocol
Point-to-Point Tunneling Protocol
Pre-shared Key
Pan-Tilt-Zoom
Recovery Agent
Registration Authority
Rapid Application Development
Remote Authentication Dial-in User Server
Redundant Array of Inexpensive Disks
Remote Access Server
Remote Access Trojan
Role-based Access Control
Rule-based Access Control
Rivest Cipher version 4
Remote Desktop Protocol
Representational State Transfer
Radio Frequency Identifier
RACE Integrity Primitives
Evaluation Message Digest
Return on Investment
Risk Management Framework
Recovery Point Objective
Rivest, Shamir, & Adleman
Remotely Triggered Black Hole
Recovery Time Objective
Real-time Operating System
Real-time Transport Protocol
Secure/Multipurpose Internet Mail Extensions
Software as a Service
Security Assertions Markup Language
Storage Area Network
Subject Alternative Name
System Control and Data Acquisition
Security Content Automation Protocol
Simple Certificate Enrollment Protocol
Secure Copy
Small Computer System Interface
Software Development Kit
Software Development Life Cycle
Software Development Life Cycle Methodology
Software Defined Network
Self-encrypting Drive

MSP
MTBF
MTTF
MTTR
MTU
NAC
NAT
NDA
NFC
NGAC
NIDS
NIPS
NIST
NTFS
NTLM
NTP
OAUTH
OCSP
OID
OS
OTA
OVAL
P12
P2P
PaaS
PAC
PAM
PAP
PAT
PBKDF2
PBX
PCAP
PEAP
PED
PEM
PFS
PFX
PGP
PHI
PII
PIV

CompTIA Security+ Certification Exam Objectives Version 7.0 (Exam Number: SY0-501)

ROI
RMF
RPO
RSA
RTBH
RTO
RTOS
RTP
S/MIME
SaaS
SAML
SAN
SAN
SCADA
SCAP
SCEP
SCP
SCSI
SDK
SDLC
SDLM
SDN
SED

ACRONYM

SPELLED OUT

ACRONYM

SPELLED OUT

SEH
SFTP
SHA
SHTTP
SIEM
SIM
SIP
SIPS
SLA
SLE
SMB
SMS
SMTP
SMTPS
SNMP
SOAP
SoC
SPF
SPIM
SPoF
SQL
SRTP
SSD
SSH
SSID
SSL
SSO
SSP
STP
TACACS+

Structured Exception Handler
Secured File Transfer Protocol
Secure Hashing Algorithm
Secure Hypertext Transfer Protocol
Security Information and Event Management
Subscriber Identity Module
Session Initiation Protocol
Session Initiation Protocol Secure
Service Level Agreement
Single Loss Expectancy
Server Message Block
Short Message Service
Simple Mail Transfer Protocol
Simple Mail Transfer Protocol Secure
Simple Network Management Protocol
Simple Object Access Protocol
System on Chip
Sender Policy Framework
Spam over Internet Messaging
Single Point of Failure
Structured Query Language
Secure Real-Time Protocol
Solid State Drive
Secure Shell
Service Set Identifier
Secure Sockets Layer
Single Sign-on
System Security Plan
Shielded Twisted Pair
Terminal Access Controller Access
Control System Plus
Total Cost of Ownership
Transmission Control Protocol/Internet Protocol
Ticket Granting Ticket
Temporal Key Integrity Protocol
Transport Layer Security
Time-based One-time Password
Trusted Platform Module
Transaction Signature
User Acceptance Testing
User Datagram Protocol
Unified Extensible Firmware Interface
Uninterruptable Power Supply
Uniform Resource Identifier
Universal Resource Locator
Universal Serial Bus

USB OTG
UTM
UTP
VDE
VDI
VLAN
VLSM
VM
VoIP
VPN
VTC
WAF
WAP
WEP
WIDS
WIPS
WORM
WPA
WPA2
WPS
WTLS
XML
XOR
XSRF
XSS

USB On The Go
Unified Threat Management
Unshielded Twisted Pair
Virtual Desktop Environment
Virtual Desktop Infrastructure
Virtual Local Area Network
Variable Length Subnet Masking
Virtual Machine
Voice over IP
Virtual Private Network
Video Teleconferencing
Web Application Firewall
Wireless Access Point
Wired Equivalent Privacy
Wireless Intrusion Detection System
Wireless Intrusion Prevention System
Write Once Read Many
WiFi Protected Access
WiFi Protected Access 2
WiFi Protected Setup
Wireless TLS
Extensible Markup Language
Exclusive Or
Cross-site Request Forgery
Cross-site Scripting

TCO
TCP/IP
TGT
TKIP
TLS
TOTP
TPM
TSIG
UAT
UDP
UEFI
UPS
URI
URL
USB

CompTIA Security+ Certification Exam Objectives Version 7.0 (Exam Number: SY0-501)

Security+ Proposed Hardware and Software List
CompTIA has included this sample list of hardware and software to assist
candidates as they prepare for the Security+ exam. This list may also be helpful
for training companies that wish to create a lab component to their training
offering. The bulleted lists below each topic are sample lists and not exhaustive.
EQUIPMENT

HARDWARE TOOLS

• Router
• Firewall
• Access point
• Switch
• IDS/IPS
• Server
• Content filter
• Client
• Mobile device
• VPN concentrator
• UTM
• Enterprise security managers/SIEM suite
• Load balancer
• Proxies
• DLP appliance
• ICS or similar systems
• Network access control servers
• DDoS mitigation hardware

• WiFi analyzers
• Hardware debuggers

SPARE PARTS/HARDWARE

• Keyboards
• Mice
• Network cables
• Monitors
• Wireless and Bluetooth dongles

SOFTWARE TOOLS AND SOFTWARE TOOLS

• Exploitation distributions (e.g., Kali)
• Proxy server
• Virtualization software
• Virtualized appliances
• Wireshark
• tcpdump
• NMAP
• OpenVAS
• Metasploit/Metaspoitable2
• Back Orifice
• Cain & Abel
• John the Ripper
• pfSense
• Security Onion
• Roo
• Any UTM
OTHER

• SourceForge

© 2017 CompTIA Properties, LLC, used under license by CompTIA Certifications, LLC. All rights reserved. All certification programs and education related to such
programs are operated exclusively by CompTIA Certifications, LLC. CompTIA is a registered trademark of CompTIA Properties, LLC in the U.S. and internationally.
Other brands and company names mentioned herein may be trademarks or service marks of CompTIA Properties, LLC or of their respective owners. Reproduction or dissemination prohibited without written consent of CompTIA Properties, LLC. Printed in the U.S. 03626-Mar2017


