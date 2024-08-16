# Domain Controller Health Check
Directory Operations

```
"3dc1.za.dov" | .\get-DCHealth.ps1 -email -report -json 
```
## Connectivity Checks
1. WinRM (Port 5985) test-wsman -computerName $computerName -erroraction SilentlyContinue
2. Ping (ICMP echo) test-connection -computername $computerName -quiet
3. WMI (Port 445) Get-WmiObject -computerName $computerName -class win32_operatingsystem -erroraction SilentlyContinue

## Parse the Domain from the FQDN
  - $pos= $computerName.IndexOf(".")
  - $hostName = $computername.Substring(0,$pos)
  - $domain = $computername.Substring($pos+1)

## Operating System
  - WMI
      - (Get-WmiObject Win32_OperatingSystem -computerName $computerName).Caption

## Manufacturer & BIOS
  - WinRM
     - invoke-command -computerName $computerName -scriptblock {get-computerinfo}

## Scan Ports
1. Port 135 RPC/DCOM Service Control Manager
2. Port 389 LDAP
3. Port 3268 Global Catalog
4. Port 636 LDAPS
5. Port 3269 Global Catalog over SSL
6. Port 3389 Remote Desktop (RDP)
7. Port 9389 Active Directory Web Services (PowerShell)
8. Port 53 DNS
9. Port 88 Kerberos Authentication
10. Port 464 Kerberos PWD
11. Port 5985 WinRM (PowerShell) is MSFT implementation of WS-Management

## Network Connections
WinRM

1. 135 RPC/DCOM Service Control Manager
2. 389 LDAP
3. 636 LDAPS
4. 3268 Global Catalog
5. 3269 Global Catalog over SSL
6. 88 Kerberos 
7. 464 Kerberos Password
8. 53 DNS
9. 445 SMB

## Memory
WinRM
- invoke-command -ComputerName $computerName -ScriptBlock {(systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim()}
- invoke-command -ComputerName $computerName -ScriptBlock {(systeminfo | Select-String 'Available Physical Memory:').ToString().Split(':')[1].Trim()}

## Certificates
WinRM
- invoke-command -ComputerName $computerName -ScriptBlock {Get-ChildItem -Path cert:\LocalMachine\My -Recurse | format-table -auto -property Subject,Issuer,NotAfter,EnhancedKeyUsageList}

## Disk Encryption
WinRM
- invoke-command -ComputerName $computerName -scriptblock {manage-bde -status}

## Replication
WinRM
- winrs -r:$computerName repadmin /queue

## GC Status
WinRM
- winrs -r:$computerName repadmin /options

## Patch OU
WinRM
- get-adobject -filter {((objectClass -like "computer")-and(name -like $HostdcName))} -SearchBase "DC=va,DC=gov" -Properties DistinguishedName -server "va.gov:3268"

## File System
WinRM
- get-childitem [file://$computerName/c$]\\$computerName\c$ -File

## DNS EnableGlobalNamesSupport
WinRM
- reg query [file://$computerName/HKLM/SYSTEM/CurrentControlSet/Services/DNS/Parameters]\\$computerName\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v "EnableGlobalNamesSupport"

## Up Time
WMI
- Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computerName
- $boottime=$wmi.ConvertToDateTime($wmi.LastBootUpTime)

## CRL
CRL Validity Extension
WinRM
- Invoke-Command -ComputerName $computerName {Get-ItemProperty -Path HKLM:System\CurrentControlSet\Services\KDC -name CRLValidityExtensionPeriod | Select-Object CRLValidityExtensionPeriod}
CRL Prefetch Task

## Services
WMI
- DNS
- Replication
- DNS Cache
- Netlogon
- NimbusWatcherService
- BESClent

## DNS Records
- A Record
- PTR Record

## Quest Change Auditor
WinRM
- Get-Service -Displayname "Quest Change*" -computername $computerName -ErrorAction stop

## Disk Status
WMI
- ([wmi][file://$computerName/root/cimv2:Win32_logicalDisk.DeviceID='c:']\\$computerName\root\cimv2:Win32_logicalDisk.DeviceID='c:')

## Remote Management
- Dell Machine
- Cloud Machine

## Splunk Universal Forwarder
WinRM
- Invoke-Command -ComputerName $computerName {Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SplunkForwarder.remove -Name ImagePath -ErrorAction SilentlyContinue}

## SCCM
WinRM
- Invoke-Command -ComputerName $computerName {Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CcmExec -Name ImagePath -ErrorAction SilentlyContinue}

## SCCM Site Code
WinRM
- $([WmiClass][file://$computerName/ROOT/ccm:SMS_Client]\\$computerName\ROOT\ccm:SMS_Client).getassignedsite() | Select-Object sSiteCode

## Device Tag
WinRM
- Invoke-Command -ComputerName $computerName {Get-ItemPropertyValue -Path "HKLM:\\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" -Name 'Group'}

## Time Source
WinRM
- Invoke-Command -ComputerName $computerName {Get-ItemPropertyValue -Path "HKLM:\\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -name Type}

## SNMP
- Get-Service -ComputerName $computerName SNMP
Valid Communities
WinRM
- Invoke-Command -ComputerName $computerName {Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities}

## Extension Attribute 12
- get-adcomputer -filter {Name -eq $SHostName} -Server $Domain -properties *
- $exAt12 = $CompObj.ExtensionAttribute12

## Goup Membership OIT ITOPS SD CIS AD Defender Clients
- (get-adcomputer -filter {samAccountName -eq $EndDollarDCFlatName } -properties MemberOf -server va.gov:3268 | Select-object MemberOf).MemberOf

## Directory Information Tree
WinRM
- "\\"+$computerName+"\G$\Windows\NTDS\ntds.dit"

## Events
WMI
Event 21 failed smart card logon
- Get-WinEvent -computername $computerName -FilterHashtable @{ logname = "System"; ID = "21"; StartTime = [datetime]::today} -ErrorAction SilentlyContinue
Event 29 KDC Smart card event
- Get-WinEvent -computername $computerName -FilterHashtable @{ logname = "System"; ID = "29"; StartTime = [datetime]::today} -ErrorAction SilentlyContinue


## Show Repl

## DC Diag
