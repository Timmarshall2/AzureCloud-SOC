# AzureCloud-Security Operations Center & Honeynet (Live Traffic)

## Introduction

In this project, I leveraged Microsoft Azure to create a honeynet and ingest logs from various resources into a Log Analytics workspace. Furthermore, I used Microsoft Sentinel to create attack maps, trigger alerts, and incidents over a 24 hour period to record and analyze an insecure environment. After gathering the metrics of the 24 hour insecure environment, I then recorded those metrics,created a geographical map of my attackers' location and applied security contols based off of the NIST 800- 53 guidelines to harden the enviroment. After assessment and authorization of those guidelines, I then monitored the network for another 24 hours and recorded the metrics post monitorization.

# SOC & Honeynet Lab Architecture 
![Cloud Honeynet | Security Operations Center](https://i.imgur.com/nXMZzw6.png)

## Architecture

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel


## Publications 

The Publications utilized in this lab are as follows:  

- NIST SP 800-53 r4
- NIST SP 800-61 r2
- NIST SP 800-37 r2


## Metrics Gathered

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)


## Architecture Before Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/EBjAyUL.png)

In the "BEFORE" metrics, all resources were originally deployed with high exposure to the internet. The Virtual Machines were configured with their NSGs and built-in firewalls set to allow "all traffic", and all other resources were also deployed with public endpoints that were visible to the internet.

## Attack Maps Before Hardening / Security Controls
![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/qYaX6mA.png)<br>
![Linux Syslog Auth Failures](https://i.imgur.com/RwiEBVi.png)<br>
![Windows RDP/SMB Auth Failures](https://i.imgur.com/gUkjZ7L.png)<br>
![Windows/ SQL Auth Failures](https://i.imgur.com/lStc9zi.png)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2023-05-10 15:20:34
Stop Time 2023-05-11 15:20:34

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 243736
| Syslog                   | 3456
| SecurityAlert            | 2
| SecurityIncident         | 162
| NSG Inbound Malicious Flows Allowed | 419

![Azure Enviroment Security Score](https://i.imgur.com/OurIlC7.png)

## Network Hardening Procedures
After the 24 hour implemetation period of the insecure enviroment, I gathered my data, selected new controls and implemented those controls utilizing NIST SP 800-53 r4. My main focus for this lab was the standards associated with SC.7.*. Additional assessments for SC-7 Boundary Protection

![SC.7.*. Additional assessments for SC-7 Boundary Protection](https://i.imgur.com/EH1dkRp.png)

## Architecture After Hardening / Security Controls
![Architecture Diagram](https://i.imgur.com/8PgEPhp.png)



During the Hardening phase, I prohibited ALL traffic except for my admin workstation to my NSG's, while all other resources were safeguarded by their built-in firewalls. I also implemeted Private Endpoints .



## Attack Maps After Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2023-05-12 15:09
Stop Time	2023-05-13 15:09

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 628
| Syslog                   | 23
| SecurityAlert            | 0
| SecurityIncident         | 0
| NSG Inbound Malicious Flows Allowed | 0

Upon ending this lab I created a compliance report at which later I would like to learn how to create a full POAM. 
![Compliance Report Results](https://i.imgur.com/fi6uFAf.png)

## Overall Improvement

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 99.74%
| Syslog                   | 99.33%
| SecurityAlert            | 100.00%
| SecurityIncident         | 100.00%
| NSG Inbound Malicious Flows Allowed | 100.00%


## Utilizing NIST 800.61r2 Computer Incident Handling Guide
During this lab I leveraged the attacks made on my honeynet to conduct my own incident response utilizing NIST SP 800-61 r2.
![Incident Response Diagram](https://i.imgur.com/AwqK6MF.png)

# Preparation
- The lab was configured to ingest all of the logs into Log Analytics Workspace, and send those logs to Microsoft Sentinel where I configured incident rules so an alert will trigger upon violation of those rules. 

# Detection & Analysis
- An incident was triggered involving a potential brute force success against Azure Active Directory
  ![Incident Alert](https://i.imgur.com/CTEVTOu.png)

- Verify the authenticity of the alert or report by utilizing the KQL query made to identify the alert. You can use that KQL to query Logs in the Log Analytics workspace to verify.
  - ![KQL Query Verification](https://i.imgur.com/r9L9z85.png)

- Immediately identify affected user and identify the origin of the attacker and determine if the attacker is involved in any lateral movement. 
   ![Lat Move| attacker Origin](https://i.imgur.com/Xv6nXTq.png)
   -  The Attackers IP is 4.196.184.6 . It looks as if all other events are connected to this one alert. (The 12 unsuccessful attempts) 
- 	Assess the potential impact of the incident.
-	What type of account was it?
-	What Roles did it have?
-	How long has it been since the breach went unattended?

   ![Assigned Roles](https://i.imgur.com/OPugAsd.png)

# Containment Eradication & Recovery

- Immediately Revoke Sessions/Access for affected user
 ![Uder Revocation](https://i.imgur.com/6XPTZmX.png)
 
 - Reset the affected user’s password and Roles if applicable
 - Enable MFA

## Client Report
The following is a fictitious report of the incident that I would give to the client: 
![Client Report](https://i.imgur.com/slyTBLt.png)

## Conclusion

In this project, I utilized Microsoft Azure to create a honeynet and ingest logs from various resources into a Log Analytics workspace. Microsoft Sentinel was used to create attack maps, trigger alerts, and incidents. I then gathered metrics over a 48-hour period to display the significance of properly configuring cloud assets with security in mind. By implementing one section of NIST SP 800-53 r4 I was able to drastically reduce the number of security events and significantly increase the overall security posture. For events triggered, I was able to utilize live traffic I was able to triage and conduct Incident Response utlizing the NIST 800-61 r2 Incidnet Handling Guide. In conclusion, I created an Alert/ Incident Report that I would give to my client informing them of the recommendations I would utilze moving forward. 

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.



## Credits
This project was inspired by Josh Madakor.
