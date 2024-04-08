# SOC-Detection-Lab


## Objective

The primary goal of this lab is to become more comfortable in a Security Operations Center (SOC) environment by utilizing Wazuh. It involves understanding how to identify and create alerts for dynamic malicious file names, forwarding them to various platforms such as email, and sending SIEM alerts to TheHive for case management to facilitate incident response.

### Skills Learned

- Experienced in configuring and familiar with the Wazuh SIEM (Security Information and Event Management) platform.
- Ability to create local rules in Wazuh for malicious file detection.
- Utilizing TheHive5 for alert management
- Understanding how to foward the hash of malicous files towards VirusTotal for threat intelligence to enhance incident response.
 
  
### Tools Used

- Wazuh (SIEM)
- Sysmon
- TheHive
- Shuffle Automation
- Mimikatz
- DigitalOcean
- VirusTotal
  
## General Knowledge
Before we begin I will give a litle background on Wazuh, Shuffle Automation, Sysmon, VirusTotal, DigitalOcean, Mimikatz, and TheHive.
<br>
<br>
Wazuh is a open-source SIEM (Security Information and Event Management) platform that helps detect, respond to, and manage security threats across their IT infrastructure.
<br>
<br>
Shuffle Automation is an open-source SOAR solution that can provide many automation services, such as EDR to tickets, automated data enrichment, and responsive capabilities.
<br>
<br>
Sysmon, short for System Monitor, is a Windows system service and device driver developed by Microsoft. It provides advanced logging and monitoring capabilities to help detect and investigate suspicious or malicious activity on Windows systems.
<br>
<br>
VirusTotal is a free online service that analyzes files and URLs to identify malware and other security threats. It aggregates multiple antivirus engines and various scanning tools to provide users with comprehensive insights into the safety of files and websites.
<br>
<br>
DigitalOcean is a cloud infrastructure provider that offers cloud computing services to help developers deploy, manage, and scale applications more easily.
<br>
<br>
Mimikatz is a cybersecurity tool used by both ethical hackers and malicious actors to retrieve sensitive data, especially passwords, from computer systems. 
<br>
<br>
TheHive is an open-source security incident response platform designed to help organizations manage and analyze security incidents efficiently.
## Lab Logial Diagram:
![Screenshot 2024-04-07 214321](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/de3c55ac-83af-4dae-9d12-fbb7f6804622)

This is the logical diagram of the lab environment. I will utilize three operating systems, including a Windows 10 virtual machine (VM) designated as the client and two Ubuntu machines that reside in the cloud. The Windows 10 client will have Sysmon and the Wazuh agent installed for telemetry enrichment. The two Ubuntu machines will be deployed from DigitalOcean, with one hosting a Wazuh server and the other hosting TheHive.
<br>
<br>
The Windows 10 client will send all events to the Wazuh manager over the internet. Alerts from the Wazuh Manager will be sent to Shuffle.io, which will enrich IOCs with the assistance of Virustotal. Additionally, Shuffle will forward that data to TheHive for case management and send an email to the SOC analyst to initialize incident response.

<br>
<br>


## Steps
I already had a Windows 10 Pro VM deployed on VirtualBox. It already had Sysmon installed from previous labs, and I will utilize it for this lab.

<br>

Ref 1: Creating Droplets on DigitalOcean:
![Creating Droplets](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/086a5013-76e3-4f5b-90a2-531744994a74)
Stating on DigitalOcean, I will create a droplet which is basically a virtual machine (vm). I will select Ubuntu version 22.04, basic shared CPU and Premium intel NVme SSD. I selected the premium Intel option so I'm able to select specifically 8 GB/2 intel CPUs. I chose that because for Wazuh manager, it's recommended to have at least 4GB of ram and 2vCPU.

<br>
<br>





