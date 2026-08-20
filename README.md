# Cognevance Technologies — Enterprise Security Monitoring & Incident Response System

## Project 3 — Advanced

This project is an educational, local-lab implementation of an enterprise-style security monitoring and incident response workflow.

### Objectives
- Design a secure enterprise network architecture.
- Implement a SIEM-style log collection and analysis workflow.
- Monitor authentication and system activity.
- Detect suspicious events.
- Generate alerts for analyst review.
- Document incident-response workflows.
- Perform risk assessment and security-hardening recommendations.
- Produce security reports, dashboards, and architecture documentation.

### Lab Scope
Use only authorized systems and isolated/local lab environments. The project does not target external systems.

### Suggested Stack
- Kali Linux or another Linux lab VM
- ELK Stack (Elasticsearch, Logstash, Kibana) or Splunk in an authorized lab
- Local log sources
- Python for defensive log analysis
- VirtualBox/VMware for the lab network

### Workflow
```text
Lab Hosts
   |
   v
Log Sources
   |
   v
Log Collection
   |
   v
SIEM / Log Analyzer
   |
   +------> Alerts ------> Analyst Review
   |                         |
   v                         v
Dashboard              Incident Response
                             |
                             v
                         Final Report
```

### Local Demo
If this repository includes a Python analyzer:
```bash
python src/log_monitor.py data/sample_auth.log
```

### Project Deliverables
1. Security monitoring setup
2. SIEM configuration
3. Incident response report
4. Security dashboard/output
5. Project documentation
6. Architecture diagram
7. GitHub repository

### Evidence
Screenshots in this repository must be captured from the student's own authorized lab. Sample logs are for demonstration only and must not be presented as real-world evidence.

### Security Notice
Only perform monitoring, testing, or incident-response exercises on systems you own or have explicit permission to assess.
