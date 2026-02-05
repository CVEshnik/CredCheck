# CredCheck
During pentesting, I realized I was spending too much time testing default credentials across different services and protocols. So I teamed up with a colleague who had a tool called [NmapAnalyzer](https://github.com/cvebezr/NmapAnalyzer).
The result was CredCheck — it analyzes output from NmapAnalyzer and attempts to try default credentials on every service it encounters.

# How to use CredCheck

After cloning the repository, you need to run [NmapAnalyzer](https://github.com/cvebezr/NmapAnalyzer).
```
./NmapAnalyzer.py 192.168.1.0/24 -D credcheck_scan --credcheck
```

After the scan completes, a directory named "СС" will be created with the required structure.
```
scan_directory/
├── 22/
│   └── hosts.txt
├── 21/
│   └── hosts.txt
├── 5432/
│   └── hosts.txt
└── 3306/
    └── hosts.txt
```
The directory name corresponds to the port that [NmapAnalyzer](https://github.com/cvebezr/NmapAnalyzer) discovered. Inside, there is a hosts.txt file containing a list of the hosts found.

Next, run CredCheck, specifying the FULL path to the "CC" directory.
```
./CredCheck.py /home/user/scans/CC
```
# Configuring the password database and software compatibility.

* **Default passwords**
Standard passwords are stored in the **standard_credentials** file. You can add or remove any other entries as needed.

* **Software compatibility**
Currently, my tool supports testing the following services: SSH, FTP, Telnet, PostgreSQL, Microsoft SQL Server, MySQL/MariaDB, RDP, SMTP, SNMP, Redis, and RabbitMQ.

The tool has been tested on Kali Linux 2025.4.
