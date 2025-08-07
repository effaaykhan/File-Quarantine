# File-Quarantine
This repo contains the complete guide to quarantine any sensitive file after any modification using wazuh's FIM module

## Wazuh Agent Configuration
Step 1. Add the Sensitive Folder path in ossec.conf to enable monitoring of that particular folder

``` directories> realtime="yes">C:\Path to sensitive folder</directories>```

Step 2. Create a python script ```quarantine.py``` and add the ```content``` in the file
Step 3. Make it executable

``` pyinstaller -F quarantine.py```

Step 4. Move the executable file to the C:\Program Files (x86)\ossec-agent\active-response\bin\

## Wazuh-Server Configuration
Step 1. In ```/var/ossec/etc/ossec.conf``` add the following active-response block

```
<command>
    <name>quarantine_win</name>
    <executable>YOUR-ACTIVE-RESPONSE-EXECUTABLE-NAME</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>quarantine_win</command>
    <location>local</location>
    <rules_id>Place your rule id which is getting triggered on file addition</rules_id>
    <timeout>120</timeout>
  </active-response>

Step 2. Add the following rule for quarantine
```
```
<group name="custom_quarantine_monitoring,syscheck,">

  <rule id="110001" level="10">
    <if_sid>100300</if_sid> <!-- base rule: File added -->
    <match>c:\\wazuh-quarantine\\</match> <!-- Here add the name of the quarantine folder getting monitored -->
    <description>File moved to  quarantine directory</description>
    <group>custom,quarantine_alert,syscheck,</group>
  </rule>

</group>
```

<img width="1284" height="226" alt="image" src="https://github.com/user-attachments/assets/b88d8c52-59ef-40bd-9fc9-ffd0f0c4e6f7" />
