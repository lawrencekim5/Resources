

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

      used to test connectivity to remote systems and verify domain name resolution. Can be used to test security posture
      by verifying that routers, firewalls, IPSs clock ICMP traffic when configured to do so. 

- netstat

      Shows TCP/IP statistics for a system. Allows you to view active TCP connections

- tracert

      Lists the routers between two systems. Each router is referred to as a hop. Tracert identifies the IP addresses, sometimes the host name
      of the hop, and the RTT (round trip time) for each hop. Tracert can help identify faulty routers and modified paths.
   
- nslookup/dig

      

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

**Transitive trust**


### 4.2 Given a scenario, install and configure identity and access services.

**LDAP**

      Lightweight Directory Access Protocol

**Kerberos**

      Kerberos is a network authentication protocol used in Windows Active Directory domains or in Unix realms. 
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

**OpenID Connect**

**OAUTH**

**Shibboleth**

**Secure token**

      Tokens AKA key fobs are small electronic devices that have an LCD that displays a number that changes periodically (Ex: 60 s).
      Tokens are synced with servers, creating a TOTP. 

**NTLM**

      New technology LAN Manager is a suite of protocols that provide authentication, integrity, and confidentiality in Windows systems.
      NTLM has three versions which are all not recommended for usage.
      - NTLM: MD4 hash of password. MD4 has been cracked
      - NTLMv2: Challenge response authentication protocol. Uses HMAC-MD5 hash of username, password, domainname, time
      - NTLM2 Session: adds mutual authentication to NTLMv2


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

- Recovery
   
      Identity must be verified before a password is reset. The administrator should provide a temporary password
      tha the user changes later to make sure that only one person knows the password.

- Disablement
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


