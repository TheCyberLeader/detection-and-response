# Detection and Response 🔍

![Status](https://img.shields.io/badge/Status-Complete-success)
![Projects](https://img.shields.io/badge/Projects-5-blue)
![Skills](https://img.shields.io/badge/Skills-Incident%20Response%20%7C%20Phishing%20Analysis%20%7C%20Log%20Analysis-informational)

## Table of Contents
- [Overview](#overview)
- [Portfolio Quick Reference](#-portfolio-quick-reference)
- [Skills Demonstrated](#skills-demonstrated)
- [Project 1: Ransomware Incident Response](#-project-1-ransomware-incident-response)
- [Project 2: Phishing Email Analysis & Triage](#-project-2-phishing-email-analysis--triage)
- [Project 3: Network Traffic Analysis with Wireshark](#-project-3-network-traffic-analysis-with-wireshark)
- [Project 4: Web Application Security Incident Investigation](#-project-4-web-application-security-incident-investigation)
- [Project 5: Security Log Analysis & Correlation](#-project-5-security-log-analysis--correlation)
- [Skills & Tools Demonstrated](#-skills--tools-demonstrated)
- [Technical Competencies](#technical-competencies)
- [Key Learning Outcomes](#key-learning-outcomes)

---

## Overview
**Note: These projects are educational examples. All scenarios are simulated for learning purposes and demonstrate the practical application of industry-standard incident response frameworks.**

This portfolio demonstrates hands-on technical skills in **detecting, analyzing, and responding to cybersecurity incidents**. Each project showcases the complete incident response lifecycle, from initial detection through containment, eradication, and recovery, following NIST and industry-standard frameworks.

**Key Question Addressed**: How do we systematically detect security incidents, analyze their scope and impact, respond effectively to minimize damage, and document findings for continuous improvement?

---

## 📊 Portfolio Quick Reference
| Metric | Value |
|--------|-------|
| **Total Projects** | 5 |
| **Primary Frameworks** | NIST Incident Response Lifecycle, Pyramid of Pain |
| **Key Skills** | Incident Documentation, Phishing Analysis, Network Traffic Analysis, Log Analysis, Threat Investigation |
| **Focus Areas** | Detection, Analysis, Containment, Documentation, Root Cause Analysis |

---

## Skills Demonstrated
- NIST Incident Response Lifecycle (Detection, Analysis, Containment, Eradication, Recovery)
- Incident handler journal documentation and tracking
- Phishing email analysis and threat intelligence correlation
- Alert ticket triage and escalation procedures
- Network traffic analysis using packet capture tools
- Security log parsing and anomaly detection
- Root cause analysis and vulnerability identification
- Incident response playbook development and execution
- Executive-level incident reporting and communication
- Post-incident remediation recommendations
- Threat indicator extraction and analysis
- Security Operations Center (SOC) Level 1 analyst workflows

---

## 🚨 Project 1: Ransomware Incident Response
**Note: This is an educational simulation designed to demonstrate NIST incident response framework application**

### Project Description
A small U.S. healthcare clinic experienced a ransomware attack that encrypted critical patient data and disrupted business operations. I documented the incident using an incident handler's journal, following the NIST Incident Response Lifecycle to track detection, analysis, and initial containment activities. This project demonstrates systematic incident documentation and application of cybersecurity frameworks during active security events.

---

### Incident Summary

**Organization Profile:**
- **Type**: Small U.S. healthcare clinic
- **Specialty**: Primary care services
- **Critical Systems**: Patient medical records, scheduling software, billing systems
- **Incident Time**: Tuesday, 9:00 AM
- **Initial Detection**: Multiple employees unable to access files

---

### Incident Timeline

**Detection Phase (9:00 AM):**
1. Multiple employees report inability to access computer files
2. Medical records system becomes inaccessible
3. Business operations forced to halt
4. Ransom note displayed on affected systems

**Initial Analysis:**
- Ransomware identified as attack vector
- Organized threat actor group identified
- Industries targeted: Healthcare and transportation
- Financial motivation confirmed (ransom demand)

---

### Attack Vector Analysis

**Initial Compromise:**
- **Method**: Targeted phishing emails
- **Recipients**: Multiple company employees
- **Payload**: Malicious email attachment
- **Execution**: Malware installed upon download

**Attack Progression:**
1. Phishing email sent to employees
2. Malicious attachment downloaded
3. Malware executed on employee workstation
4. Lateral movement within network
5. Ransomware deployed across systems
6. Critical files encrypted
7. Ransom note displayed

---

### The 5 W's Analysis

**Who:**
- **Threat Actor**: Organized group of unethical hackers
- **Known Targets**: Healthcare and transportation industries
- **Motivation**: Financial gain

**What:**
- **Incident Type**: Ransomware attack
- **Impact**: Critical file encryption, business disruption
- **Scope**: Company-wide system compromise

**When:**
- **Date**: Tuesday morning
- **Time**: 9:00 AM
- **Duration**: Ongoing (active incident)

**Where:**
- **Location**: Small U.S. healthcare clinic
- **Systems Affected**: File servers, workstations, patient data systems
- **Network Scope**: Enterprise-wide

**Why:**
- **Root Cause**: Successful phishing attack
- **Vulnerability Exploited**: Insufficient email security controls and user awareness
- **Attacker Motivation**: Financial extortion via ransom demand

---

### Incident Response Actions (NIST Framework)

**Phase 1: Detection and Analysis**
- Incident detection via user reports
- Scope assessment across multiple systems
- Threat actor identification
- Attack vector analysis
- Contacted external organizations for technical assistance
- Evidence collection and preservation

**Phase 2: Containment, Eradication, and Recovery**
- **Immediate Actions**:
  - Shutdown of affected computer systems
  - Network isolation to prevent spread
  - Engagement of incident response partners
  - Coordination with external security teams

**Organizations Contacted:**
- Technical assistance providers
- Law enforcement agencies
- Cyber insurance providers
- Forensic investigation teams

---

### Critical Questions for Investigation

**Prevention Analysis:**
1. How could the healthcare clinic prevent similar incidents?
   - Implementation of email filtering and anti-phishing controls
   - Regular security awareness training
   - Multi-factor authentication deployment
   - Network segmentation
   - Regular backup verification and testing

2. Should the company pay the ransom?
   - **Considerations**:
     - No guarantee of decryption key delivery
     - Funds criminal enterprises
     - May encourage future attacks
     - Legal and ethical implications
   - **Recommended**: Pursue recovery through backups and technical assistance

---

### Documentation Methodology

**Incident Handler's Journal Entry:**
- **Date**: Documented in real-time
- **Entry Number**: #1 (First major incident)
- **Description**: Ransomware security incident affecting healthcare operations
- **Tools Used**: None (incident documentation and coordination)
- **5 W's**: Systematically documented for investigation continuity
- **Additional Notes**: Critical questions for follow-up investigation

**Value of Documentation:**
- Creates audit trail for legal proceedings
- Enables knowledge sharing across response teams
- Supports post-incident analysis
- Provides evidence for insurance claims
- Facilitates regulatory compliance reporting
- Informs future security improvements

---

### Key Findings

**Vulnerabilities Identified:**
1. Insufficient email security controls
2. Lack of user phishing awareness
3. Inadequate network segmentation
4. Missing endpoint protection
5. Insufficient backup and recovery procedures

**Business Impact:**
- Complete operational shutdown
- Patient care disruptions
- Revenue loss during downtime
- Potential HIPAA compliance violations
- Reputational damage
- Recovery costs

---

### Recommendations

**Immediate (0-30 days):**
1. Deploy advanced email filtering with attachment sandboxing
2. Implement application whitelisting on critical systems
3. Verify and test backup restoration procedures
4. Conduct emergency security awareness training
5. Deploy endpoint detection and response (EDR) tools

**Short-term (30-90 days):**
1. Implement network segmentation between departments
2. Deploy multi-factor authentication across all systems
3. Conduct comprehensive vulnerability assessment
4. Develop and test incident response playbooks
5. Establish relationships with incident response partners

**Long-term (90+ days):**
1. Implement Security Information and Event Management (SIEM)
2. Establish Security Operations Center (SOC) capabilities
3. Conduct regular phishing simulation exercises
4. Develop comprehensive business continuity plans
5. Regular penetration testing and red team exercises

---

### Summary: Ransomware Incident Response

I successfully documented a complex ransomware incident using the NIST Incident Response Lifecycle framework and incident handler's journal methodology. The documentation demonstrates:

1. **Systematic Analysis** - Comprehensive 5 W's investigation framework
2. **Framework Application** - NIST Incident Response Lifecycle phases
3. **Critical Thinking** - Strategic questions about ransom payment and prevention
4. **Professional Documentation** - Structured journal entry for continuity
5. **Strategic Recommendations** - Tiered remediation roadmap

This incident response capability supports effective coordination during active security events and provides foundation for continuous security improvement.

[🔝 Back to Top](#table-of-contents)

---

## 📧 Project 2: Phishing Email Analysis & Triage
**Note: This is an educational simulation designed to demonstrate SOC analyst phishing analysis skills**

### Project Description

A potential phishing email was detected in the organization's email system, containing a suspicious attachment claiming to be a password-protected resume. I conducted a comprehensive analysis following the organization's Phishing Incident Response Playbook, including threat intelligence correlation, alert ticket documentation, and escalation procedures. This project demonstrates Level 1 SOC analyst capabilities for email threat analysis and incident triage.

---

### Alert Details

**Alert Ticket Information:**
- **Incident Type**: Suspected phishing email
- **Detection Method**: Email security system alert
- **Priority**: Medium (requires investigation)
- **Status**: Under investigation

**Email Metadata:**
```
From: Def Communications <76tguyhh6tgftrt7tg.su> <114.114.114.114>
Sent: Wednesday, July 20, 2025 09:30:14 AM
To: hr@inergy.com <176.157.125.93>
Subject: Re: Infrastructure Egnieer role
Attachment: bfsvc.exe
```

**Known Malicious Indicator:**
- **File Hash**: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b
- **Type**: SHA-256 hash
- **Status**: Confirmed malicious

---

### Email Content Analysis

**Message Body:**
```
Dear HR at Ingergy,

I am writing for to express my interest in the engineer role 
posted from the website.

There is attached my resume and cover letter. For privacy, 
the file is password protected. Use the password paradise10789 
to open.

Thank you,

Clyde West
```

**Red Flags Identified:**

1. **Grammatical Errors:**
   - "I am writing for to express" (incorrect grammar)
   - "There is attached" (awkward phrasing)
   - "Ingergy" vs. "Inergy" (company name misspelling)

2. **Subject Line Issues:**
   - "Re:" prefix implies previous conversation (none exists)
   - Misspelled job title: "Egnieer" instead of "Engineer"

3. **Sender Domain Indicators:**
   - Suspicious TLD: `.su` (Soviet Union, often used by threat actors)
   - Random characters in domain: `76tguyhh6tgftrt7tg.su`
   - Company name mismatch: "Def Communications" vs. HR inquiry

4. **Attachment Analysis:**
   - **Filename**: `bfsvc.exe`
   - **Extension**: `.exe` (executable, not document)
   - Claims to be "resume and cover letter" but is executable
   - Password protection claim is social engineering tactic

5. **IP Address Analysis:**
   - Sender IP: `114.114.114.114` (Chinese DNS server IP)
   - Geographic mismatch with claimed sender identity
   - Receiver IP: `176.157.125.93` (requires validation)

---

### Phishing Incident Response Playbook

**Step 1: Receive Phishing Alert**
✅ Alert received and ticket created

**Step 2: Evaluate the Alert**

**Alert Severity Assessment:**
- **Severity**: High (requires immediate escalation)
- **Reason**: Confirmed malicious file hash, executable attachment

**Receiver Details:**
- Email: hr@inergy.com
- IP: 176.157.125.93
- Department: Human Resources

**Sender Details:**
- Email: 76tguyhh6tgftrt7tg.su
- IP: 114.114.114.114
- Domain reputation: Suspicious

**Subject Line Analysis:**
- "Re: Infrastructure Egnieer role"
- Typo suggests automated/rushed attack
- False reply chain (social engineering)

**Message Body Review:**
- Multiple grammatical errors
- Social engineering tactics (password protection claim)
- Urgency implied (job application context)

**Step 3.0: Does the email contain any links or attachments?**
✅ Yes - Contains attachment: `bfsvc.exe`

**Step 3.1: Are the links or attachments malicious?**

**Threat Intelligence Analysis:**
- **File**: bfsvc.exe
- **Hash**: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b
- **Verification**: Cross-referenced against known malicious hash database
- **Result**: ✅ CONFIRMED MALICIOUS

**VirusTotal Analysis (Simulated):**
- Detection Ratio: High
- Malware Type: Trojan/Backdoor
- Risk Level: Critical

---

### Pyramid of Pain Analysis

The Pyramid of Pain framework helps understand the difficulty attackers face when defenders detect and block different indicators:

**Level 1: Hash Values (Trivial for Attackers)**
- **Current Indicator**: File hash `54e6ea47...`
- **Defender Advantage**: Easy to detect with signature
- **Attacker Effort to Evade**: Trivial (recompile malware)
- **Value**: Good for immediate blocking, poor long-term

**Level 2: IP Addresses (Easy for Attackers)**
- **Current Indicator**: 114.114.114.114
- **Defender Action**: Block sender IP
- **Attacker Effort to Evade**: Easy (change IP/VPS)

**Level 3: Domain Names (Simple for Attackers)**
- **Current Indicator**: 76tguyhh6tgftrt7tg.su
- **Defender Action**: Block domain
- **Attacker Effort to Evade**: Simple (register new domain)

**Level 4: Network/Host Artifacts (Annoying)**
- Behavioral patterns
- Registry changes
- File system artifacts

**Level 5: Tools (Challenging)**
- Malware family identification
- Tool signature detection

**Level 6: TTPs (Tough)**
- Social engineering methodology
- Phishing campaign patterns
- HR-targeted attacks

**Strategic Defense Approach:**
Focus on detecting TTPs (tactics, techniques, procedures) for long-term resilience:
- Employee phishing awareness training
- Email authentication (SPF, DKIM, DMARC)
- Attachment sandboxing
- Behavioral analysis
- User verification procedures for job applications

---

### Investigation Findings

**Confirmed Indicators of Compromise (IOCs):**
1. Malicious file hash (SHA-256)
2. Suspicious sender domain (.su TLD)
3. Executable masquerading as document
4. Social engineering tactics
5. Grammatical anomalies
6. Geographic/linguistic inconsistencies

**Attack Vector:**
- Spear phishing targeting HR department
- Social engineering (job application pretext)
- Malicious executable delivery
- Password protection claim to evade email gateways

**Potential Impact if Successful:**
- Initial access to corporate network
- Credential theft
- Lateral movement capabilities
- Data exfiltration
- Ransomware deployment

---

### Alert Ticket Response

**Step 3.2: Update Alert Ticket and Escalate**

**Summary of Findings:**
```
ESCALATION REQUIRED - CONFIRMED MALICIOUS PHISHING EMAIL

Investigation Summary:
- Analyzed phishing email sent to hr@inergy.com
- Identified malicious attachment: bfsvc.exe
- Confirmed malicious file hash via threat intelligence
- Multiple red flags identified (see detailed analysis)

Indicators of Compromise:
- File Hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b
- Sender IP: 114.114.114.114
- Sender Domain: 76tguyhh6tgftrt7tg.su
- Attachment: bfsvc.exe (executable masquerading as resume)

Risk Assessment:
- Severity: HIGH
- Potential Impact: Initial access, malware deployment
- Requires immediate response

Reason for Escalation:
Confirmed malicious executable attachment verified against 
known threat intelligence. Immediate containment required to 
prevent potential compromise.

Recommended Actions:
1. Quarantine/delete email from all mailboxes
2. Block sender domain and IP at email gateway
3. Verify no employees opened attachment
4. Conduct forensic analysis if attachment was executed
5. Update threat intelligence database
6. Conduct targeted security awareness training for HR

Analyst: MW
Ticket Status: ESCALATED
Escalation Time: 11:30 AM
Escalated To: Level 2 SOC Analyst
```

---

### Containment and Remediation Actions

**Immediate Actions (Completed):**
1. ✅ Alert ticket created and documented
2. ✅ Threat intelligence correlation performed
3. ✅ Malicious indicators confirmed
4. ✅ Ticket escalated to Level 2 SOC analyst
5. ✅ Summary and findings documented

**Level 2 SOC Follow-up Actions:**
1. Email quarantine across organization
2. Sender domain/IP blocking at email gateway
3. Endpoint verification (check if attachment opened)
4. Forensic analysis if execution detected
5. Threat intelligence platform update
6. Targeted user awareness campaign

**Long-term Prevention:**
1. Enhanced email filtering rules
2. Attachment sandboxing implementation
3. User phishing simulation training
4. Email authentication protocols (SPF/DKIM/DMARC)
5. HR-specific security awareness training
6. Job application verification procedures

---

### Skills Demonstrated

**Technical Analysis:**
- Email header analysis
- File hash correlation with threat intelligence
- Indicator of Compromise (IOC) identification
- Social engineering tactic recognition
- Domain reputation assessment

**Framework Application:**
- Phishing Incident Response Playbook execution
- Pyramid of Pain strategic analysis
- Structured alert ticket documentation
- Escalation procedure adherence

**Communication:**
- Clear executive summary
- Technical findings documentation
- Actionable recommendations
- Professional escalation justification

---

### Summary: Phishing Email Analysis

I successfully analyzed a sophisticated phishing email following SOC Level 1 analyst procedures, including threat intelligence correlation, playbook execution, and professional escalation. The investigation demonstrates:

1. **Systematic Analysis** - Comprehensive email examination using structured methodology
2. **Threat Intelligence** - File hash verification and malicious indicator confirmation
3. **Playbook Adherence** - Step-by-step phishing response playbook execution
4. **Strategic Thinking** - Pyramid of Pain framework for long-term defense
5. **Professional Communication** - Clear escalation with actionable recommendations

This phishing analysis capability supports rapid detection and response to email-based threats while providing strategic insights for organizational security improvement.

[🔝 Back to Top](#table-of-contents)

---

## 🔍 Project 3: Network Traffic Analysis with Wireshark
**Note: This is an educational simulation designed to demonstrate packet capture analysis skills**

### Project Description

Network traffic analysis is critical for detecting malicious activity, investigating security incidents, and understanding network behavior. I used Wireshark, an industry-standard network protocol analyzer, to examine packet capture (PCAP) files and identify security-relevant network patterns. This project demonstrates the ability to analyze network traffic for security investigations and incident response.

---

### Tool Overview: Wireshark

**What is Wireshark?**
- Open-source network protocol analyzer
- Graphical user interface for packet inspection
- Cross-platform (Windows, macOS, Linux)
- Industry-standard tool for network analysis

**Key Capabilities:**
- Real-time packet capture and analysis
- Deep packet inspection
- Protocol decoding (hundreds of protocols)
- Display filtering and search
- Export capabilities for evidence preservation

**Security Value:**
- Detect malicious network activity
- Investigate security incidents
- Analyze malware network behavior
- Verify security control effectiveness
- Troubleshoot network issues
- Collect forensic evidence

---

### Analysis Workflow

**Packet Capture Examination Process:**

1. **File Loading:**
   - Import PCAP file into Wireshark
   - Verify packet count and capture timeframe
   - Review capture statistics

2. **Initial Assessment:**
   - Identify protocols present
   - Review conversation statistics
   - Identify source/destination patterns
   - Note any anomalies in traffic volume

3. **Protocol Analysis:**
   - HTTP/HTTPS traffic examination
   - DNS query analysis
   - TCP connection patterns
   - Unusual protocol usage

4. **Traffic Filtering:**
   - Apply display filters for targeted analysis
   - Isolate specific conversations
   - Search for known indicators
   - Extract relevant packets

5. **Evidence Collection:**
   - Export filtered packets
   - Document findings
   - Preserve chain of custody
   - Generate analysis reports

---

### Common Analysis Scenarios

**Malware Communication Detection:**
- Unusual outbound connections
- Beaconing behavior (regular intervals)
- Data exfiltration patterns
- Command and control (C2) traffic

**Intrusion Detection:**
- Port scanning activity
- Exploitation attempts
- Lateral movement indicators
- Privilege escalation traffic

**Data Leak Investigation:**
- Large outbound transfers
- Unusual file transfers
- Unauthorized protocol usage
- Encryption anomalies

**Network Reconnaissance:**
- DNS enumeration
- Network mapping traffic
- Service discovery attempts
- Vulnerability scanning

---

### Key Wireshark Features for Security Analysis

**Display Filters:**
```
ip.addr == 192.168.1.100          # Specific IP
http.request.method == "POST"     # HTTP POST requests
dns.qry.name contains "malicious" # DNS queries
tcp.flags.syn == 1                # TCP SYN packets
```

**Protocol Hierarchy:**
- View distribution of protocols
- Identify unusual protocol usage
- Detect protocol anomalies

**Conversations:**
- Endpoint communication mapping
- Connection volume analysis
- Duration and data transfer metrics

**Expert Information:**
- Automatic anomaly detection
- Protocol warnings and errors
- Performance issues

**Follow TCP Stream:**
- Reconstruct full conversations
- View complete data exchanges
- Extract transferred files

---

**Date**: July 25, 2025
**Entry**: #2
**Description**: Analyzing suspicious network traffic packet capture

**Tool(s) Used:**
Wireshark - Network protocol analyzer with graphical user interface. Enables security analysts to capture and analyze network traffic for detecting and investigating malicious activity.

**The 5 W's:**
- **Who**: Unknown external IP address (203.0.113.45)
- **What**: Suspicious outbound network traffic detected by IDS
- **When**: July 25, 2025, 2:30 PM - 3:45 PM
- **Where**: Internal network segment (192.168.10.0/24)
- **Why**: Potential data exfiltration or command and control communication

**Additional Notes:**
First hands-on experience using Wireshark for incident investigation. Analyzed PCAP file containing network traffic from a potentially compromised workstation. Identified unusual DNS queries and HTTP POST requests to unfamiliar domains. The packet-level visibility provided by Wireshark was invaluable for understanding the communication patterns. Successfully isolated suspicious traffic and documented findings for escalation to senior analyst.

---

### Skills Developed

**Technical Capabilities:**
- PCAP file analysis
- Network protocol understanding
- Display filter creation and application
- Traffic pattern recognition
- Packet-level inspection
- Data extraction from captures

**Analytical Skills:**
- Anomaly detection in network traffic
- Baseline behavior establishment
- Investigation hypothesis development
- Evidence correlation across packets
- Timeline reconstruction

**Security Applications:**
- Incident investigation support
- Threat hunting capabilities
- Malware behavior analysis
- Network baseline development
- Security control validation

---

### Practical Applications

**Incident Response:**
- Post-incident network traffic analysis
- Lateral movement detection
- Data exfiltration identification
- Attack timeline reconstruction

**Threat Hunting:**
- Proactive threat identification
- Behavioral anomaly detection
- Indicator of Compromise (IOC) hunting
- Zero-day detection

**Security Operations:**
- Alert validation and enrichment
- False positive reduction
- Investigation workflow enhancement
- Evidence collection for escalation

**Compliance and Forensics:**
- Audit trail verification
- Regulatory compliance evidence
- Legal investigation support
- Chain of custody maintenance

---

### Skills Developed

**Tool Proficiency:**
- Wireshark interface navigation
- Filter syntax and application
- Protocol decoder usage
- Export and reporting capabilities

**Security Insights:**
- Network traffic normal vs. anomalous
- Common attack patterns in network data
- Protocol-specific security considerations
- Investigation workflow optimization

**Professional Development:**
- Industry-standard tool experience
- Forensic evidence handling
- Technical documentation skills
- Security investigation methodology

---

### Summary: Network Traffic Analysis

I successfully developed foundational Wireshark skills for security analysis and incident investigation. The experience demonstrates:

1. **Tool Proficiency** - Wireshark interface navigation and basic analysis capabilities
2. **Security Mindset** - Understanding network traffic as investigation evidence
3. **Analytical Approach** - Systematic packet examination methodology
4. **Professional Documentation** - Incident handler journal entry for knowledge retention
5. **Continuous Learning** - Recognition of tool complexity and ongoing skill development

This network traffic analysis capability provides essential foundation for incident response, threat hunting, and security investigations.

[🔝 Back to Top](#table-of-contents)

---

## 🌐 Project 4: Web Application Security Incident Investigation
**Note: This is an educational simulation designed to demonstrate incident investigation and reporting skills**

### Project Description

A security incident involving unauthorized access to customer data required comprehensive investigation, root cause analysis, and executive reporting. I conducted a thorough investigation of a web application vulnerability exploitation, documented findings in an incident final report, and developed strategic remediation recommendations. This project demonstrates advanced incident investigation skills and executive-level security communication.

---

### Executive Summary

**Incident Overview:**
- **Date**: December 28, 2025
- **Time**: 7:20 PM PT
- **Type**: Data breach via web application vulnerability
- **Impact**: 50,000 customer records compromised
- **Data Exposed**: Personal Identifiable Information (PII) and financial information
- **Estimated Financial Impact**: $100,000 direct costs + potential revenue loss
- **Current Status**: Incident closed, investigation complete

---

### Incident Timeline

**Initial Extortion Attempt:**

**December 22, 2025 - 3:13 PM PT:**
- Employee receives email from external address
- Sender claims successful theft of customer data
- Initial ransom demand: $25,000 cryptocurrency
- Employee assumes spam and deletes email
- **Critical Mistake**: Failure to report to security team

**Escalation and Confirmation:**

**December 28, 2025:**
- Same employee receives second email from same sender
- Email includes sample of stolen customer data (proof of breach)
- Increased ransom demand: $50,000 cryptocurrency
- Employee reports to security team
- Security team mobilized for investigation

**Investigation Period:**

**December 28-31, 2025:**
- Security team conducts on-site investigation
- Root cause analysis performed
- Scope determination (extent of data theft)
- Attack vector identification
- Log analysis and timeline reconstruction

---

### Investigation Findings

**Root Cause Identified:**

**Vulnerability Type:**
- Insecure Direct Object Reference (IDOR)
- CWE-639: Authorization Bypass Through User-Controlled Key
- OWASP Top 10: Broken Access Control (A01:2021)

**Technical Details:**
- **Application**: E-commerce web application
- **Vulnerable Component**: Purchase confirmation page
- **Attack Method**: Forced browsing attack
- **Exploitation**: URL parameter manipulation

**Attack Mechanism:**
```
Normal URL: https://example.com/order/confirmation?order_id=12345
Attacker URL: https://example.com/order/confirmation?order_id=12346
```

**Vulnerability Explanation:**
The application did not verify that the authenticated user was authorized to access the order confirmation page. By incrementing the order number in the URL, the attacker could access any customer's purchase confirmation page without authentication or authorization checks.

---

### Attack Analysis

**Attacker Methodology:**

1. **Discovery Phase:**
   - Attacker made legitimate purchase
   - Received order confirmation URL
   - Identified order_id parameter in URL

2. **Vulnerability Testing:**
   - Modified order_id parameter
   - Accessed other customers' confirmation pages
   - Confirmed lack of authorization checks

3. **Automated Exploitation:**
   - Developed script to enumerate order numbers
   - Sequentially accessed thousands of confirmation pages
   - Systematically collected customer data

4. **Data Exfiltration:**
   - Extracted customer information from each page
   - Compiled database of stolen records
   - Approximately 50,000 records compromised

5. **Extortion:**
   - Initial contact with ransom demand
   - Provided proof of breach (data samples)
   - Increased demands when ignored

---

### Log Analysis Evidence

**Web Server Access Logs:**

**Anomaly Detected:**
- Single source IP address
- Exceptionally high volume of requests
- Sequential order number pattern
- Automated behavior characteristics

**Attack Pattern:**
```
[Timestamp] 192.168.100.50 GET /order/confirmation?order_id=10001
[Timestamp] 192.168.100.50 GET /order/confirmation?order_id=10002
[Timestamp] 192.168.100.50 GET /order/confirmation?order_id=10003
...
[Timestamp] 192.168.100.50 GET /order/confirmation?order_id=60000
```

**Key Indicators:**
- Requests from single IP over short timeframe
- Perfect sequential order number enumeration
- No normal browsing patterns (direct URL access only)
- High request rate (automated script)
- No authentication challenges triggered

---

### Data Exposed

**Customer Information Compromised:**
1. Personal Identifiable Information (PII):
   - Full names
   - Email addresses
   - Physical addresses
   - Phone numbers

2. Financial Information:
   - Credit card (partial, last 4 digits)
   - Transaction amounts
   - Purchase history
   - Billing addresses

3. Order Details:
   - Product information
   - Purchase dates
   - Delivery information
   - Order numbers

**Total Records**: Approximately 50,000 customers

---

### Response and Remediation

**Immediate Response Actions:**

1. **Public Relations:**
   - Collaborated with PR department
   - Developed customer notification strategy
   - Transparent disclosure of breach details
   - Media response coordination

2. **Customer Support:**
   - Direct notification to all affected customers
   - Free identity protection services offered
   - Dedicated support hotline established
   - FAQ documentation published

3. **Technical Investigation:**
   - Complete web server log analysis
   - Attack vector confirmation
   - Scope determination
   - Evidence preservation for legal proceedings

4. **Regulatory Compliance:**
   - Notification to relevant authorities
   - Documentation for compliance reporting
   - Legal counsel engagement
   - Insurance claim initiation

---

### Technical Remediation

**Immediate Fixes (Deployed):**

1. **Access Control Implementation:**
   - User authentication verification before page access
   - Authorization check: verify user owns requested order
   - Session validation for all transactions
   - Secure direct object reference implementation

2. **URL Parameter Validation:**
   - Order ID tied to authenticated user session
   - Encrypted order reference tokens
   - Elimination of predictable sequential IDs

**Code Fix Example:**
```python
# BEFORE (Vulnerable)
@app.route('/order/confirmation')
def order_confirmation():
    order_id = request.args.get('order_id')
    order = get_order(order_id)  # No authorization check
    return render_template('confirmation.html', order=order)

# AFTER (Secure)
@app.route('/order/confirmation')
@login_required
def order_confirmation():
    order_id = request.args.get('order_id')
    order = get_order(order_id)
    
    # Verify user owns this order
    if order.user_id != current_user.id:
        abort(403)  # Forbidden
    
    return render_template('confirmation.html', order=order)
```

---

### Strategic Recommendations

**Preventive Measures:**

**1. Security Development Lifecycle:**
- Implement secure coding standards
- Code review requirements for all changes
- Security testing before production deployment
- OWASP Top 10 training for developers

**2. Vulnerability Management:**
- **Routine Vulnerability Scans**:
  - Quarterly automated scanning
  - Manual penetration testing annually
  - Bug bounty program consideration
- **Regular Penetration Testing**:
  - Annual third-party assessment
  - Focus on web application security
  - Include social engineering testing

**3. Access Control Mechanisms:**

**A. Allowlisting Implementation:**
- Define authorized URL patterns
- Automatically block out-of-range requests
- Implement at web application firewall (WAF)
- Log all blocked attempts

**B. Authentication and Authorization:**
- Ensure only authenticated users access content
- Verify user authorization for each resource
- Implement role-based access control (RBAC)
- Session management security enhancements

**4. Monitoring and Detection:**
- Web application firewall (WAF) deployment
- Anomaly detection for access patterns
- Alert on sequential resource enumeration
- Real-time security monitoring (SIEM)

**5. Data Protection:**
- Minimize data displayed on confirmation pages
- Implement data masking for sensitive information
- Encryption for data at rest and in transit
- Regular data access audits

---

### Business Impact Assessment

**Financial Impact:**
- **Direct Costs**: $100,000
  - Investigation expenses
  - Legal fees
  - Identity protection services
  - PR and communications
  - Remediation development
  - Compliance penalties (potential)

- **Indirect Costs**:
  - Customer trust degradation
  - Potential revenue loss
  - Competitive disadvantage
  - Increased insurance premiums
  - Long-term reputation damage

**Operational Impact:**
- Emergency response mobilization
- Development team reassignment
- Customer service workload increase
- Executive time investment
- Ongoing monitoring requirements

**Regulatory Impact:**
- Mandatory breach notifications
- Potential fines and penalties
- Increased regulatory scrutiny
- Compliance audit requirements
- Documentation obligations

---

### Lessons Learned

**Security Gaps Identified:**
1. Insufficient access control implementation
2. Lack of authorization verification
3. Predictable resource identifiers
4. Missing security monitoring
5. Delayed incident reporting by staff

**Process Improvements:**
1. Security awareness training mandatory
2. Incident reporting procedures clarified
3. Suspicious email escalation protocol
4. Regular security testing integration
5. Development security requirements

**Cultural Changes:**
1. Security-first mindset development
2. Encouraging staff to report concerns
3. No punishment for security reports
4. Transparency and communication
5. Continuous learning emphasis

---

### Summary: Web Application Security Incident

I successfully conducted a comprehensive security incident investigation from detection through remediation, demonstrating advanced capabilities in:

1. **Root Cause Analysis** - Identified IDOR vulnerability through systematic log analysis
2. **Executive Communication** - Delivered clear, actionable incident report for leadership
3. **Technical Investigation** - Analyzed web server logs to reconstruct attack timeline
4. **Strategic Remediation** - Developed tiered recommendations (immediate and long-term)
5. **Business Impact Assessment** - Quantified financial and operational consequences

This investigation showcases the ability to manage complex security incidents from technical analysis through executive reporting and strategic improvement planning.

[🔝 Back to Top](#table-of-contents)

---

## 📊 Project 5: Security Log Analysis & Correlation
**Note: This is an educational simulation designed to demonstrate log analysis and investigation skills**

### Project Description

Security log analysis is fundamental to detecting threats, investigating incidents, and maintaining visibility across IT infrastructure. I analyzed security logs from multiple systems (web servers, mail servers, vendor systems) to identify anomalies, detect potential security incidents, and correlate events across different log sources. This project demonstrates systematic log analysis methodology and multi-source event correlation.

---

### Log Analysis Environment

**Systems Monitored:**

1. **Web Servers (www1, www2, www3):**
   - Apache/Nginx access logs
   - Security event logs
   - Authentication attempts
   - Traffic patterns

2. **Mail Server (mailsv):**
   - Email traffic logs
   - Authentication events
   - Spam/phishing attempts
   - Relay attempts

3. **Vendor Systems (vendor_sales):**
   - Application logs
   - Transaction records
   - User activity
   - System events

**Log Files Analyzed:**
```
www1/
  ├── access.log (4.3 MB - HTTP requests)
  └── secure.log (1.2 MB - Authentication/security events)

www2/
  ├── access.log (4.0 MB - HTTP requests)
  └── secure.log (1.1 MB - Authentication/security events)

www3/
  ├── access.log (4.0 MB - HTTP requests)
  └── secure.log (1.1 MB - Authentication/security events)

mailsv/
  └── secure.log (1.1 MB - Mail security events)

vendor_sales/
  └── vendor_sales.log (2.1 MB - Transaction logs)
```

**Total Log Data**: ~18.9 MB across 9 log files

---

### Analysis Methodology

**Log Analysis Framework:**

**1. Data Collection:**
- Gather logs from all relevant systems
- Verify log completeness and integrity
- Establish analysis timeframe
- Document chain of custody

**2. Normalization:**
- Standardize timestamp formats
- Parse log formats (Apache, syslog, custom)
- Extract key fields (IP, user, action, timestamp)
- Handle multi-line entries

**3. Baseline Establishment:**
- Normal traffic patterns identification
- Typical authentication behavior
- Expected transaction volumes
- Regular maintenance activities

**4. Anomaly Detection:**
- Volume anomalies (traffic spikes/drops)
- Timing anomalies (unusual hours)
- Geographic anomalies (unexpected locations)
- Behavioral anomalies (unusual patterns)

**5. Correlation:**
- Cross-reference events across systems
- Timeline reconstruction
- Lateral movement detection
- Attack chain identification

**6. Investigation:**
- Deep-dive on suspicious events
- User behavior analysis
- Threat intelligence correlation
- Evidence preservation

---

### Common Log Analysis Techniques

**Command-Line Analysis:**

**Basic Log Inspection:**
```bash
# View recent log entries
tail -100 access.log

# Search for specific IP
grep "192.168.1.100" access.log

# Count HTTP status codes
grep "\" 404 " access.log | wc -l

# Find failed login attempts
grep "Failed password" secure.log
```

**Advanced Pattern Detection:**
```bash
# Top 10 IP addresses by request volume
cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Failed authentication attempts per hour
grep "Failed password" secure.log | cut -d' ' -f1-3 | uniq -c

# Identify potential scanning activity
awk '{print $1}' access.log | sort | uniq -c | awk '$1 > 100 {print $2}'

# Extract suspicious user agents
grep -i "bot\|scan\|crawl" access.log | awk -F'"' '{print $6}' | sort | uniq
```

---

### Investigation Scenarios

**Scenario 1: Failed Authentication Attempts**

**Detection:**
```bash
grep "Failed password" mailsv/secure.log | head -20
```

**Analysis Questions:**
- How many failed attempts per user?
- Are attempts from same or different IPs?
- Is this a brute force attack?
- Are any accounts compromised?

**Investigation Steps:**
1. Count failed attempts per username
2. Identify source IP addresses
3. Check for successful logins after failures
4. Correlate with other systems
5. Determine if account lockout triggered

**Indicators of Compromise:**
- Hundreds of failures for single account
- Dictionary attack patterns
- Distributed source IPs (botnet)
- Credential stuffing attempts

---

**Scenario 2: Web Server Anomaly Detection**

**Detection:**
```bash
# Unusual HTTP status codes
grep "\" 404 " www1/access.log | wc -l
grep "\" 403 " www1/access.log | wc -l
grep "\" 500 " www1/access.log | wc -l
```

**Analysis Questions:**
- Why spike in 404 errors?
- Is someone scanning for files?
- Are there SQL injection attempts?
- Path traversal attempts?

**Investigation Steps:**
1. Identify requested URLs causing errors
2. Check for common attack patterns
3. Analyze request frequency and timing
4. Review user agent strings
5. Correlate with IDS/IPS alerts

**Red Flags:**
```
/admin/config.php
/wp-admin/
/../../../etc/passwd
/phpMyAdmin/
/backup.sql
```

---

**Scenario 3: Data Exfiltration Detection**

**Detection:**
```bash
# Large outbound transfers
awk '{sum[$1]+=$10} END {for (ip in sum) print ip, sum[ip]}' access.log | sort -k2 -rn
```

**Analysis Questions:**
- Who is downloading large amounts of data?
- Is this authorized business activity?
- Are backups or archives being exfiltrated?
- Is this account compromised?

**Investigation Steps:**
1. Identify users with unusual download volumes
2. Review types of files accessed
3. Check access times (after hours?)
4. Verify business justification
5. Check data classification of accessed files

---

**Scenario 4: Lateral Movement Detection**

**Detection:**
Correlate authentication logs across systems:

```bash
# User authentication timeline
grep "username123" */secure.log | sort -k1
```

**Analysis Questions:**
- Is user accessing systems they normally use?
- Rapid authentication across multiple systems?
- Privileged access from unusual systems?
- After-hours administrative activity?

**Investigation Steps:**
1. Map user's normal system access
2. Identify deviations from baseline
3. Check for privilege escalation
4. Review administrative command history
5. Correlate with other security events

---

### Multi-Source Correlation Example

**Attack Chain Reconstruction:**

**Step 1: Initial Compromise (mailsv)**
```
[2025-07-20 09:30] Failed password for admin from 114.114.114.114
[2025-07-20 09:31] Failed password for admin from 114.114.114.114
[2025-07-20 09:32] Accepted password for admin from 114.114.114.114
```

**Step 2: Reconnaissance (www1)**
```
[2025-07-20 09:35] 114.114.114.114 GET /admin/users.php
[2025-07-20 09:35] 114.114.114.114 GET /admin/config.php
[2025-07-20 09:36] 114.114.114.114 GET /backup/
```

**Step 3: Data Access (vendor_sales)**
```
[2025-07-20 09:40] admin accessed customer_database
[2025-07-20 09:42] admin exported customer_records.csv
[2025-07-20 09:43] admin downloaded sales_report_2025.pdf
```

**Step 4: Exfiltration (www1)**
```
[2025-07-20 09:45] 114.114.114.114 POST /upload/external
[2025-07-20 09:45] Large outbound transfer detected (250 MB)
```

**Correlation Insight:**
Same IP address progressed through attack stages across multiple systems within 15 minutes, indicating coordinated automated attack.

---

### Tools and Techniques

**Log Analysis Tools:**
- **grep/awk/sed**: Pattern matching and text processing
- **sort/uniq**: Data aggregation and deduplication
- **cut/awk**: Field extraction
- **wc**: Counting and statistics
- **tail/head**: Recent event review

**Advanced Tools:**
- **Splunk**: Enterprise log management and SIEM
- **ELK Stack**: Elasticsearch, Logstash, Kibana
- **Graylog**: Open-source log management
- **OSSEC**: Host-based intrusion detection
- **rsyslog**: Centralized logging

**Scripting:**
```bash
#!/bin/bash
# Automated threat hunting script

echo "=== Failed Login Analysis ==="
grep "Failed password" */secure.log | \
  awk '{print $9}' | sort | uniq -c | sort -rn | head -10

echo "=== Suspicious User Agents ==="
grep -i "bot\|scan" */access.log | \
  awk -F'"' '{print $6}' | sort | uniq -c | sort -rn | head -10

echo "=== High Volume IPs ==="
cat */access.log | awk '{print $1}' | \
  sort | uniq -c | sort -rn | head -20
```

---

### Key Findings and Insights

**Normal Baseline Established:**
- Typical daily traffic volume per web server
- Expected authentication pattern
- Regular vendor transaction volume
- Standard maintenance windows

**Anomalies Detected:**
- Brute force authentication attempts
- Directory traversal attempts
- SQL injection patterns in URLs
- Unusual after-hours access
- Geographic anomalies in access patterns

**Security Improvements:**
- Centralized logging implementation needed
- Real-time alerting for critical events
- Automated anomaly detection
- Log retention policy enforcement
- Security Information and Event Management (SIEM)

---

### Skills Demonstrated

**Technical Proficiency:**
- Linux command-line log analysis
- Regular expression pattern matching
- Data parsing and normalization
- Multi-source log correlation
- Timeline reconstruction

**Analytical Capabilities:**
- Baseline establishment
- Anomaly detection
- Attack pattern recognition
- Evidence correlation
- Root cause identification

**Investigation Methodology:**
- Systematic analysis approach
- Hypothesis development and testing
- Evidence preservation
- Chain of custody maintenance
- Finding documentation

---

### Summary: Security Log Analysis

I successfully conducted comprehensive security log analysis across multiple systems, demonstrating:

1. **Multi-Source Analysis** - Correlation of events across web servers, mail servers, and applications
2. **Systematic Methodology** - Structured approach from data collection through investigation
3. **Technical Proficiency** - Command-line tools and scripting for log analysis
4. **Threat Detection** - Identification of attack patterns and security anomalies
5. **Investigation Skills** - Timeline reconstruction and attack chain analysis

This log analysis capability provides foundation for threat hunting, incident investigation, and continuous security monitoring.

[🔝 Back to Top](#table-of-contents)

---

## 🎯 Skills & Tools Demonstrated

### Security Frameworks & Methodologies
![NIST Incident Response](https://img.shields.io/badge/NIST_Incident_Response-0066CC?style=flat)
![Pyramid of Pain](https://img.shields.io/badge/Pyramid_of_Pain-FF6B6B?style=flat)
![5 W's Analysis](https://img.shields.io/badge/5_W's_Analysis-4479A1?style=flat)

### Security Tools
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat)
![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=flat)
![Log Analysis](https://img.shields.io/badge/Log_Analysis-95E1D3?style=flat)
![PCAP Analysis](https://img.shields.io/badge/PCAP_Analysis-4ECDC4?style=flat)

### Documentation & Communication
![Incident Handler's Journal](https://img.shields.io/badge/Incident_Journal-4EAA25?style=flat)
![Alert Tickets](https://img.shields.io/badge/Alert_Tickets-003545?style=flat)
![Executive Reports](https://img.shields.io/badge/Executive_Reports-FCC624?style=flat)
![Playbooks](https://img.shields.io/badge/Playbooks-FF6B6B?style=flat)

---

## Technical Competencies

| Competency Area | Specific Skills |
|-----------------|----------------|
| **Incident Response** | NIST IR lifecycle, incident documentation, root cause analysis, containment strategies, eradication procedures, recovery planning, post-incident reporting |
| **Threat Analysis** | Phishing email analysis, social engineering detection, threat actor profiling, indicator of compromise (IOC) extraction, threat intelligence correlation, malware hash analysis |
| **Network Analysis** | Wireshark packet capture analysis, protocol decoding, traffic pattern recognition, network baseline establishment, anomaly detection, data exfiltration identification |
| **Log Analysis** | Multi-source log correlation, timeline reconstruction, attack chain analysis, Linux command-line analysis, pattern detection with grep/awk, automated threat hunting |
| **Investigation** | Evidence collection and preservation, chain of custody, forensic analysis, scope determination, impact assessment, timeline reconstruction |
| **Documentation** | Incident handler journals, alert ticket management, executive summaries, final incident reports, playbook development, technical writing |
| **Communication** | Escalation procedures, stakeholder reporting, executive briefings, technical findings presentation, recommendation development, cross-team coordination |
| **Security Operations** | SOC Level 1 analyst workflows, alert triage, ticket escalation, playbook execution, shift handoff procedures, continuous monitoring |

---

## Key Learning Outcomes

**Incident Response Mastery:**
- Applied complete NIST Incident Response Lifecycle across multiple scenarios
- Developed systematic documentation habits using incident handler's journal
- Demonstrated ability to transition between technical analysis and executive communication
- Created actionable remediation recommendations aligned with business priorities

**Threat Detection and Analysis:**
- Executed comprehensive phishing analysis using structured playbook methodology
- Correlated threat intelligence (file hashes, IPs, domains) with security alerts
- Applied Pyramid of Pain framework for strategic defense planning
- Identified attack patterns across email, web, and network attack vectors

**Investigation Excellence:**
- Conducted root cause analysis for complex security incidents
- Performed multi-source log correlation to reconstruct attack timelines
- Demonstrated evidence preservation and chain of custody awareness
- Quantified business impact of security incidents for leadership decision-making

**Technical Proficiency:**
- Gained practical experience with industry-standard tools (Wireshark, VirusTotal)
- Developed command-line log analysis skills for threat hunting
- Built systematic approach to network traffic analysis
- Created transferable investigation methodologies

**Professional Development:**
- Demonstrated SOC analyst competencies across multiple incident types
- Developed clear technical writing for various audiences (technical, executive, operational)
- Showed ability to follow structured playbooks while applying critical thinking
- Built foundation for advancing from Level 1 to Level 2 SOC analyst roles

**Strategic Security Thinking:**
- Connected tactical incident response to strategic security improvements
- Developed preventive recommendations beyond reactive fixes
- Applied defense-in-depth principles to remediation strategies
- Considered business impact in security decision-making

This portfolio showcases readiness for Security Operations Center (SOC) analyst roles, incident response positions, and security investigation functions. The projects demonstrate both technical execution capabilities and strategic thinking required for effective cybersecurity operations.

---
## 🔗 Navigation

[⬅️ Back to Portfolio Home](https://github.com/TheCyberLeader) | [📂 View All Projects](https://github.com/TheCyberLeader/hands-on-cyber-leadership) | [📧 Contact](mailto:m@riegrc.com) | [💼 LinkedIn](https://linkedin.com/in/mariezw)

---
