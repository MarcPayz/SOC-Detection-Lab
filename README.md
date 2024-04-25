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
Starting on DigitalOcean, I will create a droplet, essentially a virtual machine (VM). I will choose Ubuntu version 22.04 with basic shared CPU and premium Intel NVMe SSD. Opting for the premium Intel option, I can select 8 GB of RAM and 2 Intel CPUs. I made this choice because for Wazuh manager, it's recommended to have at least 4 GB of RAM and 2 vCPUs.

<br>
<br>
<br>

Ref 2: Creating Firewall:
![Firewall](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/a840e4a4-3700-4289-be0b-0b5dd4087296)
Anticipating potential brute force attacks on my cloud-based VM, I implemented a firewall inbound rule allowing TCP and UDP access exclusively from my public IP address across all ports. I designated my public IP address under the shaded blue section labeled 'sources'. 

<br>
<br>
<br>

Ref 3: Adding droplet to firewall:
<br>
![Adding firewall1](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/eaf39275-0b44-442b-a74b-730ef79314a4)
<br>
![Adding firewall2](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/3cebdaeb-46ef-40ec-b9c6-b6d49a2d7a6f)
To add the droplet to the firewall, I navigated to 'Networking' and clicked on 'Edit'. Then, I chose 'Droplets' to display all available droplets and selected Wazuh, the droplet I created to host my Wazuh server. Upon completion, the message 'Firewall updated successfully' appeared in the top right corner.

<br>
<br>
<br>
Ref 4: Launching Droplet:

![Launching Droplet](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/87ac5a7d-7e11-4178-abf6-497ae3770eda)
To launch the Droplet, I navigate to 'Access' and select 'Launch Droplet Console'. I then access the Droplet via SSH by logging in as the user 'root'. To do this, I open the command prompt (cmd) and type 'ssh root@159.89.190.88', providing my credentials when prompted.

<br>
<br>
<br>
The very first thing to do when dealing with a fresh Ubuntu VM is to update everything. So, the first command I execute is 'apt-get update && apt-get upgrade'. This command updates the package index to ensure it has the latest information about available packages and upgrades the installed packages to their latest versions based on the updated package index
<br>
<br>
<br>

Ref 5: Setting up Wazuh:
![Install wazuh](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/9d4a4d92-c5ff-496c-be08-a88a91e0df4b)
I will install Wazuh using the curl command, which allows you to download files from a remote server. In this case, I downloaded Wazuh from their website. After the download is completed, it informs me that the Wazuh web interface will be accessible on port 443. This means Wazuh will be accessed via HTTPS. To access Wazuh, I need to type the Wazuh IP address, which is the Droplet IP address of the VM, into the URL and add ':443'. So it will be https://159.89.190.68:443.

<br>
<br>
<br>
Now, I will install TheHive on my second Ubuntu VM. I repeated steps 1 through 4, such as adding it to the firewall, etc. When I authenticated via SSH to access my Ubuntu VM, I executed the same command: 'apt-get update && apt-get upgrade'. <br><br>

# TheHive Prerequisites & background

Before I can install TheHive, I need to install some prerequisites. These prerequisites are outlined in TheHive's documentation and include four components: installing Java, Cassandra, Elasticsearch, and finally, TheHive itself.

<br>

To give a little background on the prerequisites TheHive needs to run: <br>
Cassandra is used as the backend database to store and manage large volumes of security-related data efficiently. This includes data such as alerts, cases, observables, and other information processed by TheHive. <br>

Elasticsearch is often used as the search and analytics engine for indexing and querying security-related data, such as alerts, cases, and observables. It provides fast and efficient search capabilities that allows users to quickly retrieve relevant information during incident response and threat analysis. <br>

Java is required because TheHive itself is a Java-based application. This means that Java must be installed on the system where TheHive is deployed in order for it to run properly. 

# Steps Continued
<br>

Ref 6: Installing Java:
![Installing Java](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/72a11ea3-55e9-42b0-a917-be765f664436)

<br>
<br>

Ref 7: Installing Cassandra: 
![Installing Cassandra](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/e5e02bf8-dde4-455c-a38f-8ebf82e97d5c)

<br>
<br>

Ref 8: Installing Elasticsearch:
![Installing ElasticSearch](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/c53265b4-4e36-4fc9-95be-62ae99ac7492)

<br>
<br>

Ref 9: Installing TheHive: 
![Installing TheHive](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/9f0e10c4-36d8-4930-8678-477d4dc9434e)

<br>
<br>
<br>
After installing everything, I will begin by editing cassandra's configuratuion files by typing in the command 'nano /etc/cassandra/cassandra.yaml'.

<br>
<br>
<br>
Ref 10: Changing the Listening Address:

![Listening addy](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/5d20ba33-e238-43a2-b7d0-923781fc8f36)
This listening address is the public IP address of TheHive which is 143.198.18.216.

<br>
<br>

Ref 11: Changing RPC address:
![RPC](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/cda849e0-8df4-4163-9a19-112920aa79ea)
The Remote Procedure Call (RPC) address refers to the network address that Cassandra nodes use to communicate to each other. In this case the RPC address also needs to be the public IP address of TheHive.

<br>
<br>
Ref 12: Changing the seed address:

![Seed Address](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/b8b611b1-800b-4f93-8eae-da7acc575cea)
The seed address refers to the IP address or hostname of one or more nodes in the cluster. In our case, the seed address is the public IP address of TheHive. The only thing I'm changing is the actual IP address, leaving the port ':7000' unchanged.

<br>
<br>
Ref 13: Starting the cassandra service:

![Starting cassandra](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/620e4366-5234-49bf-82a9-2077ef5a4905)
Now that I am done configuring Cassandra, I need to start the Cassandra service. I will utilize the command 'systemctl start cassandra.service'. To confirm that Cassandra is active, I will use the command 'systemctl status cassandra.service'. As you can see, the service is up and running.

<br>
<br>
<br>
Now to edit elasticsearch configuration files, I will utilize the command 'nano /etc/elasticsearch/elasticsearch.yml'.
<br>
<br>
Ref 14: 

![Cluster name](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/5cb32192-153b-460c-aba8-da31804532a6)
The very first thing I did was change cluser.name to 'thehive', and I removed the '#' 'for node.name: node-1' to make it active.

<br>
<br>
Ref 15: 

![more config](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/19b475a1-56a9-45ee-831a-742deed4dbca)
The network host for TheHive needs to be its public IP, which is 143.198.18.216. I removed the '#' for 'http.port: 9200' to activate HTTP communication on port 9200 for Elasticsearch. Similarly, I removed the '#' for 'cluster.initial_master_nodes' and specified only "node-1" as the initial master node because that's the only node we have. The default configuration for 'cluster.initial_master_nodes' included two nodes, so I removed the second one, leaving only ["node-1"].

<br>
<br>

Ref 16: Starting elasticsearch service: 
![starting elasticsearch](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/ad65de57-67d0-4d8d-9397-de3f5bf47c1a)
I used the command 'systemctl start elasticsearch' to start the service and 'systemctl enable elasticsearch' to enable it. To confirm the service is running, I used 'systemctl status elasticsearch', and as you can see, it is active and running.

<br>
<br>
<br>

Now I need to make sure TheHive user has access to TheHive's directory. This is necessary because TheHive user needs permission to execute TheHive's files including scipts, binaries, and other executables located within TheHive's directory.

<br>
<br>

Ref 17: Changing file ownership:
<br>
![Chown](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/5d98fa07-9b42-4bbd-9a25-daa8e53eff09)
<br>
First, I used the command 'ls -la /opt/thp' to list the details of the directory where TheHive is located. As indicated by the orange circle, the directory and group owner is currently 'root'. To change the owner and group of the directory to 'thehive', I used the command 'chown -R thehive:thehive /opt/thp'.<br><br>To break down everything in the command: <br> 
'chown' command allows me to change the ownership of the directory. <br><br>The 'R' option stands for recursive and it tells the 'chown' command to operate recursively, meaning it will change the ownership of the specified directory and all its contents, including subdirectories and files. <br><br> 'thehive:thehive' specifies the new owner and group for the /opt/thp directory. <br><br> '/opt/thp' is the directory whose ownership is being changed. <br><br> After running the previous command, I did the command, 'ls -la /opt/thp' and as you can see by the second orange circle, TheHive is both the owner (user) and group of the directory.

<br>
<br>
<br>
Now I will edit TheHive configuration files by doing the command nano /etc/thehive/application.conf
<br>
<br>
<br>
Ref 18: Editing TheHive configuration files:

![Thehive conf file](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/a5459171-56ac-4df2-b254-0360d0840f70)
In TheHive configuration files, the hostname will be the public IP address of TheHive, which is '143.198.18.216'. The cluster name is 'MPayz', which I set for Cassandra. For the second hostname, which Elasticsearch will utilize, I also set the IP address of TheHive. Regarding the service configuration under 'application.baseUrl', I set the IP address of TheHive. This means I will access TheHive at 'http://143.198.18.216:9000', with 9000 being the port number. <br><br> Next I will save the configurations made and make sure TheHive is up and running by utilizing the command 'systemctl enable thehive' followed by 'systemctl status thehive'.

<br>
<br>
<br>
Ref 19: Making sure all services are running:

![Active](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/6a53ff9d-0b1d-4de4-91d0-26dd407287e5)
Before accessing TheHive by typing 'http://143.198.18.216:9000' into a browser, I ensured that all services were running smoothly to avoid any connection issues. As you can see, all necessary services are operational.

<br>
<br>
<br>
Ref 20: Connecting to TheHive:

![TheHive](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/03157614-75bf-4e60-970b-cb8b52492850)
As you can see I sucessfully connected to TheHive and the default user is 'admin'.

<br>
<br>
<br>

The next thing to do is to add my windows 10 client as a new agent on Wazuh so I can see all logs relating to it.

<br>
<br>
<br>

Ref 21: Deploying a new agent: 
![Deploy new Agent](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/a812e132-67b4-41e1-9949-9c75d98b1a7c)
I chose Windows because it matches my Windows 10 client. For the server address, I used the public IP address of Wazuh, which is '159.89.190.88'. In the optional settings, I set my agent name as 'MPayz' and kept the 'select one or more existing groups' option at its default configuration.

<br>
<br>
<br>
Ref 22: Windows 10 client Security events:

![Sec events](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/48cec7cc-78bc-49e3-a995-7c26ffff744d)
This displays the dashboard for the Windows 10 client and Wazuh. As you can see, this dashboard presents multiple datasets originating from the Wazuh droplet, connecting via SSH, and the Windows 10 client, including security alerts. I notice there were three attempted authentication failures when connecting to my Wazuh server, and four successful authentications, all from my own activity. Additionally, there's a chart illustrating the alert level evolution, which demonstrates the severity levels of security alerts over time.

<br>
<br>
<br>

Ref 23: Editing ossec.conf file on windows 10 agent:
![ossec](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/0a1fdf1c-d871-468c-8e56-2d8309383bfa)
<br>
![config](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/1df97cb3-1f7e-4bb3-a230-5c56badadb47)
<br>
The ossec.conf file serves as the configuration file for the Wazuh agent installed on the Windows 10 client. As I've installed Sysmon to generate telemetry on the Windows 10 client, I will update the ossec.conf file to forward the data collected by Sysmon to Wazuh. What's circled indicates this modification.

<br>
<br>
<br>
Ref 24: Checking Wazuh for sysmon telemtry:

![sysmon](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/1bb58ebf-2e46-4889-b223-2c5deed8cc3d)
Heading back to Wazuh, I queried 'sysmon' in the search bar under events, and as you can see, there were 891 hits relating to Sysmon. This shows that the telemetry collected by Sysmon is successfully being aggregated towards Wazuh.

<br>
<br>
<br>

Before downloading and activating Mimikatz on my Windows 10 client, I need to modify the ossec.conf file on the Wazuh manager. By default, Wazuh only logs events when a rule or alert is triggered, so I must adjust this behavior in the ossec.conf file so it can log everything.

<br>
<br>

Ref 25: editing ossec.conf file on Wazuh manager:
![ossec wazuh manager](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/432dd07a-d4bf-4ac9-a883-bbd7f2a47198)
To edit this file, I utilized the command 'nano /var/ossec/etc/ossec.conf'. In the configuration file, under '<logall>', it previously indicated 'no', but I changed it to 'yes', and I did the same for '<logall_json>'. This change ensures that Wazuh logs everything regardless of whether a rule is set in place. Afterwards I saved and restarted the Wazuh manager service by utilizing the command 'systemctl restart wazuh-manager.service'. So now all the log files will go towards a file called 'Archives'.

<br>
<br>
To enable Wazuh to ingest logs from the 'Archives' log file, I need to configure another file. I'll do this by executing the command 'nano /etc/filebeat/filebeat.yml'.

<br>
<br>

Ref 26: filebeat.yml:
![yaml](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/3a39d2c1-0cfd-46f9-8dea-f6bc56758e2d)
The 'filebeat.yml' file is responsible for forwarding log data from various sources to Elasticsearch for indexing and analysis. Within the configuration setting 'archives' under 'filebeat.modules', I changed it from false to true. This adjustment enables Filebeat to parse and ingest logs from the Wazuh archives. After making changes to the filebeat configuration file, I will restart filebeat by utilizing the command 'systemctl restart filebeat'.

<br>
<br>
<br>

Now, I will create a new index to have a designated location where I can view all archive files. While Wazuh already includes some pre-built indexes such as alerts and other logs, I will create a specific index specifically for these archive files.

<br>
<br>

Ref 27: Creating a new index:
![Index 1](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/4d7b0696-e7b6-4629-b0f4-9a15828f090d)
<br> The first step in creating a new index was typing 'wazuh-archives*-'. This new index will allow me to view every single log that originates from the Wazuh archives files, with the wildcard specifying all content within those files.
![index2](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/d5416717-29d7-4405-bcd9-40259df34689)\
As the second step, it's asking me what specific settings I want associated with my new index, and I selected timestamp so I can see the times associated with each log.

<br>
<br>
<br>
Ref 28: Activating Mimikatz on windows 10 client:

![Mimikatz](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/473cf85d-cdfb-4e63-af50-2eb8028faf63)
Heading over to Windows 10 vm and after installing mimikatz, I activate it on the windows vm to see if Wazuh would pick it up if someone would run mimikatz on that machine. 

<br>
<br>
<br>
Ref 29: Checking Wazuh for Mimikatz:

![wazuh mimikatz](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/52ed8474-8c89-47d8-8840-dee31aecc2da)
After selecting the wazuh-archives index, I searched 'mimikatz' to make sure Wazuh picked it up, and as you can see I recieved two hits.

<br>
<br>
<br>
Ref 30: Looking at extended information:

![extended](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/4d39adfc-089e-4113-a40e-6ff1e29ee327)
Examining the extended data for one of the Mimikatz logs, we can observe various details such as the command-line query and the associated user. Additionally, we can access hash values linked to the Mimikatz file and identify the actual file name, which is 'originalFileName', which is extremely valuable information. <br> <br> Discovering the actual file name for Mimikatz is valuable information because now I can create an alert for any files that match 'originalFileName'. This means that even if the name 'mimikatz.exe' is changed to 'hello.exe' or any other name to conceal its identity, Wazuh would still alert me if someone ran Mimikatz on the Windows 10 client.

<br>
<br>
<br>

To create an alert for files that match 'originalFileName', I need to create a local rule in Wazuh. A local rule allows users to extend the default rule set provided by Wazuh to address unique use cases or enhance detection capabilities for specific threats or activities relevant to their organization.

<br>
<br>

Ref 31: Wazuh Local Rules:
![Local Rules](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/5ec38f27-9511-4b2c-9de4-6a77b40271db)
Heading over to creating local rules in wazuh, I first copied and pasted the previous rule to have a format I can use for this new rule I will make. I set the rule id to '100002' to match the format of the previous rule, and I set severity level to 15 because that's the file I'm interested in detecting. <br><br>Next for 'if_group', it specifies where the log will be coming from so I set that to 'sysmon_event1'. <br><br>Next, as for field name, I added 'originalFileName' and I set the field value to 'mimikatz\.exe' meaning its searching specifically for mimikatz in the originalFileName. <br><br>As for the description, I want it to say 'Mimikatz Usage Detected'. <br><br> For <mitre> I specified the id to 'T1003' because mimikatz is a OS credential Dumping under the Mitre ATT&CK Tactict 'Credential Access', so setting that field for the local rules will allow me to that information clearly when the alert comes by. 

<br>
<br>
<br>

Ref 32: Changing Mimikatz file name:
![diditwork](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/f98fdda9-a72c-4373-b732-ed7ef38c18e7)
Heading over to windows 10 vm, I changed the mimikatz file name to 'DiditWork' to see if Wazuh would still detect it even if I changed the file name. Afterwards, I ran the command again on cmd to activite mimikatz to activate it.

<br>
<br>
<br>
Ref 33: Checking Wazuh for DiditWork:

![log](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/863b236a-db9f-40a6-8a8e-ce07de540ed7)
In Wazuh, as you can see, a Mimikatz log was received regardless of whether the filename was changed to 'DiditWork'. We can observe various pieces of information about it, such as the MITRE technique being T1003, the tactic being Credential Access, the description stating 'Mimikatz usage detected', and the severity level set to 15. As a SOC analyst, seeing a severity level of 15 triggers a series of actions, including prioritizing this alert to respond to and mitigate the potential security incident.

<br>
<br>
<br>

Ref 34: Expanding the log:
![itworked](https://github.com/MarcPayz/SOC-Detection-Lab/assets/163923336/c98ee198-3243-4bf7-b11a-e01a8b32f4cc)
If we examine the 'data.win.eventdata.image', we can see that the user Marc executed 'DiditWork.exe', yet Wazuh still alerted me that Mimikatz was detected on this workstation. This underscores the importance of setting rules to identify alerts of malicious files based on their original file name.

<br>
<br>
<br>
Now, I will use Shuffle.io to automatically send that alert to TheHive for alert/case management and gather additional information about Mimikatz by leveraging VirusTotal for OSINT. Finally, I will send an email to the SOC analyst to inform them that Mimikatz was detected on a workstation.

<br>
<br>
<br>































































































