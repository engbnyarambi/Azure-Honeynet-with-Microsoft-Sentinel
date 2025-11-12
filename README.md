# Azure Honeynet with Microsoft Sentinel

## Overview
This project demonstrates how to architect and deploy a mini honeynet in Microsoft Azure, integrated with a Security Operations Center (SOC) using Microsoft Sentinel. It captures real-world attack telemetry, visualizes threat activity, and validates the effectiveness of security controls through live metrics and incident analysis.



## Architecture Summary
The honeynet is built using core Azure components and designed to simulate vulnerable infrastructure while enabling full visibility through centralized logging and analytics.

### Key Components:
- **Virtual Network (VNet)** with segmented subnets
- **Network Security Groups (NSGs)** allowing controlled inbound flows
- **Virtual Machines** (2 Windows, 1 Linux) exposed to the internet
- **Log Analytics Workspace** for centralized log ingestion
- **Azure Key Vault** and **Storage Account** for sensitive asset simulation
- **Microsoft Sentinel (SIEM)** for threat detection, alerting, and incident response

![Cloud Honeynet + SOC Architecture](path-to-your-diagram.png)

## 📊 Metrics & Observations

### Before Hardening (24h Exposure)
| Metric                        | Count |
|------------------------------|-------|
| SecurityEvent (Windows Logs) | 7671  |
| Syslog (Linux Logs)          | 833   |
| SecurityAlert                | 4     |
| SecurityIncident             | 59    |
| Malicious NSG Flows          | 620   |

### After Hardening (24h Exposure)
| Metric                        | Count |
|------------------------------|-------|
| SecurityEvent (Windows Logs) | 3894  |
| Syslog (Linux Logs)          | 6     |
| SecurityAlert                | 0     |
| SecurityIncident             | 0     |
| Malicious NSG Flows          | 0     |

## KQL Queries (Microsoft Sentinel)
```kql
// Security Events (Windows)
SecurityEvent
| where TimeGenerated >= ago(24h)
| count

// Syslog (Linux)
Syslog
| where TimeGenerated >= ago(24h)
| count

// Defender Alerts
SecurityAlert
| where DisplayName !startswith "CUSTOM" and !startswith "TEST"
| where TimeGenerated >= ago(24h)
| count

// Sentinel Incidents
SecurityIncident
| where TimeGenerated >= ago(24h)
| count

// NSG Malicious Flows
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```

## Goals
- Simulate real-world attack surface in Azure
- Ingest and analyze telemetry using Microsoft Sentinel
- Measure impact of hardening controls on threat visibility
- Provide a reproducible blueprint for SOC teams and security researchers

## Demo
Watch the full walkthrough on YouTube:  
**[How to Build a SOC + Honeynet in Azure](https://www.youtube.com/watch?v=your-video-link)**

## Getting Started
To replicate this setup:
1. Deploy VMs and NSGs via Azure Portal or ARM templates
2. Connect resources to a Log Analytics Workspace
3. Enable Microsoft Sentinel and configure data connectors
4. Apply KQL rules from `Sentinel-Analytics-Rules(KQL Alert Queries).json`
5. Monitor incidents and metrics over time

## Repository Contents
- `Sentinel-Analytics-Rules(KQL Alert Queries).json` – Alert logic
- `*.json` – Sample telemetry from failed auth attempts
- `geoip-summarized.csv` – Summarized geolocation data
- `Xpath.txt` – Sample XPath extraction logic

## Lessons Learned
- Even minimal exposure attracts automated scanning and brute-force attempts
- Sentinel provides powerful visibility with minimal configuration
- Hardening controls drastically reduce noise and attack surface

## 🏷️ Tags
`azure` `sentinel` `honeynet` `soc` `kql` `security-monitoring` `cloud-security` `siem`
