
# "dc1.za.dov" | .\Get-DcHealth.ps1 -email
param (
	[parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string]$computerName,
    [string]$infile = "",
	[string]$ReportPath = "C:\Scripts\DomainController-EA\Reports\DesiredStateConfiguration\",
	[switch]$computerNameDiag,
	[switch]$Quick,
	[switch]$ShowRepl,
	[switch]$smartcard,
	[switch]$time,
	[switch]$Report,
    [switch]$email,
	[string]$Header = "Domain Controller Health",
    [string]$to = "peter.pfau@live.com",
    [string]$from = "DC_Monitor@live.com",
	[string]$ver = "2023.5.7"
)
Function Get-PortStatus ($Ipaddress,$Port) {
	$ErrorActionPreference = "SilentlyContinue"
	$t = New-Object Net.Sockets.TcpClient
	$t.Connect($Ipaddress,$Port)
	   if($t.Connected){$PortState = 0}else{Write-Host "Port $Port is closed. " -BackgroundColor Red;$PortState = 1}
	return $PortState
}
$start = Get-Date
$Date = Get-Date
# // Create a Collection Table
$collDC=@()

##################################################
Write-host `nDomain Controller Health Check $ver`n
# Fix DC Incorrect Domain Entry
If ($computerName -Like "*.*"){
	write-host fqdn
	$DCFlatName = $computerName.split(".")[0]
	$ADComputerobj = Get-ADComputer -filter {Name -eq $DCFlatName} -Server "za.dov:3268"
	$computerName = $ADComputerobj.DNSHostName
}
# Fix DC Flat Name Entry
else{
	write-host flatname
	$DCFlatName = $computerName
	$ADComputerobj = Get-ADComputer -filter {Name -eq $DCFlatName} -Server "za.dov:3268"
	$computerName = $ADComputerobj.DNSHostName
}

#### Connectivity Checks
	if(test-wsman -computername $computerName -erroraction SilentlyContinue){Write-Host "WinRM Success (PowerShell Remoting)";$value="Success";$Status = "green";$WinRM = $True}else{Write-Host "WinRM Fail (PowerShell Remoting)";$value = "Failed";$status = "yellow";$WinRM=$False}
	$objDC  = New-Object psobject -Property @{Item = "WinRM";Value = $Value;Description = "PowerShell Remoting";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC
	if(test-connection -computername $computerName -quiet){Write-Host "Ping Success (ICMP)";$value="Success";$status = "green"}else{Write-Host "Ping Fail (ICMP)";$value = "Failed";$status = "yellow"}
	$objDC  = New-Object psobject -Property @{Item = "Ping";Value = $Value;Description = "ICMP";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC
	if(Get-WmiObject -ComputerName $computerName -class win32_operatingsystem -erroraction SilentlyContinue){write-host "Windows Management Instrumentation Success (WMI)";$value="Success";$Status = "green";$WMI = $True}else{Write-Host "WMI Fail";$value = "Failed";$status = "yellow";$WMI=$False}
	$objDC  = New-Object psobject -Property @{Item = "WMI";Value = $Value;Description = "Windows Managment Instrumentation";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC
	
#### Get the Domain
$pos = $computerName.IndexOf('.')
$hostDCname = $computerName.Substring(0,$pos)
$domainDC = $computerName.Substring($pos+1);$objDC  = New-Object psobject -Property @{Item = "Domain";Value = $domainDC;Description = "Realm";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
$IPAddress = [System.Net.Dns]::GetHostAddresses($computerName).IPAddressToString;$objDC  = New-Object psobject -Property @{Item = "IPAddress";Value = $IPAddress;Description = "IPv4";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
write-host $IPAddress
If ($WMI){
	$osver = (Get-WmiObject Win32_OperatingSystem -ComputerName $computerName).Caption;$objDC  = New-Object psobject -Property @{Item = "OS";Value = $osver;Description = "Operating System";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
}
if($WinRM){
	$CompBIOS = invoke-command -computername $computerName -scriptblock {get-computerinfo}
	$objDC  = New-Object psobject -Property @{Item = "Manufacturer";Value = $CompBIOS.BiosManufacturer;Description = "Manufacturer";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
	$objDC  = New-Object psobject -Property @{Item = "BIOS";Value = $CompBIOS.Biosdescription;Description = "BIOS";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
}

# https://www.grc.com/port_135.htm 
$135 = Get-PortStatus $computerName 135	
If($135 -eq 0){Write-host "Port 135 is operational";$status="green";$value="Open"}else{Write-Host "Port 135 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 135";Value = $Value;Description = "RPC/DCOM Servic Control Manager";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$389 = Get-PortStatus $computerName 389	
If($389 -eq 0){Write-host "Port 389 is operational";$status="green";$value="Open"}else{Write-Host "Port 389 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 389";Value = $Value;Description = "LDAP";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$3268 = Get-PortStatus $computerName 3268	
If($3268 -eq 0){Write-host "Port 3268 is operational";$status="green";$value="Open"}else{Write-Host "Port 3268 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 3268";Value = $Value;Description = "Global Catalog";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
if($quick.ispresent){exit}
$636 = Get-PortStatus $computerName 636	
If($636 -eq 0){Write-host "Port 636 is operational";$status="green";$value="Open"}else{Write-Host "Port 636 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 636";Value = $Value;Description = "LDAPs";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$3269 = Get-PortStatus $computerName 3269	
If($3269 -eq 0){Write-host "Port 3269 is operational";$status="green";$value="Open"}else{Write-Host "Port 3269 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 3269";Value = $Value;Description = "Global Catalog over SSL";s = $status;Date = $Date.ToString("s")};$collDC += $objDC

$3389 = Get-PortStatus $computerName 3389
If($3389 -eq 0){Write-host "Port 3389 is operational";$status="green";$value="Open"}else{Write-Host "Port 3389 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 3389";Value = $Value;Description = "Remote Desktop (RDP)";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$9389 = Get-PortStatus $computerName 9389
If($9389 -eq 0){Write-host "Port 9389 is operational";$status="green";$value="Open"}else{Write-Host "Port 9389 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 9389";Value = $Value;Description = "Active Directory Web Services (PowerShell)";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$53 = Get-PortStatus $computerName 53
If($53 -eq 0){Write-host "Port 53 is operational";$status="green";$value="Open"}else{Write-Host "Port 53 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 53";Value = $Value;Description = "DNS";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$88 = Get-PortStatus $computerName 88
If($88 -eq 0){Write-host "Port 88 is operational";$status="green";$value="Open"}else{Write-Host "Port 88 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 88";Value = $Value;Description = "Kerberos Authentication";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$464 = Get-PortStatus $computerName 464
If($464 -eq 0){Write-host "Port 464 is operational";$status="green";$value="Open"}else{Write-Host "Port 464 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 464";Value = $Value;Description = "Kerberos PWD";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$5985 = Get-PortStatus $computerName 5985
If($5985 -eq 0){Write-host "Port 5985 is operational";$status="green";$value="Open"}else{Write-Host "Port 5985 is closed **Warning";$status="yellow";$value="Closed"}
$objDC  = New-Object psobject -Property @{Item = "Port 5985";Value = $Value;Description = "WinRM (PowerShell) is MSFT implementation of WS-Management";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
# $5986 = Get-PortStatus $computerName 5986
# If($5986 -eq 0){Write-host "Port 5986 is operational";$status="green";$value="Open"}else{Write-Host "Port 5986 is closed **Warning";$status="yellow";$value="Closed"}
# $objDC  = New-Object psobject -Property @{Item = "Port 5986";Value = $Value;Description = "WinRM HTTPS";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
# $80 = Get-PortStatus $computerName 80
# If($80 -eq 0){Write-host "Port 80 is operational";$status="green";$value="Open"}else{Write-Host "Port 80 is closed **Warning";$status="yellow";$value="Closed"}
# $objDC  = New-Object psobject -Property @{Item = "Port 80";Value = $Value;Description = "HTTP";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
# $443 = Get-PortStatus $computerName 443
# If($443 -eq 0){Write-host "Port 443 is operational";$status="green";$value="Open"}else{Write-Host "Port 443 is closed **Warning";$status="yellow";$value="Closed"}
# $objDC  = New-Object psobject -Property @{Item = "Port 443";Value = $Value;Description = "HTTPS";s = $status;Date = $Date.ToString("s")};$collDC += $objDC

If($winRM){
	######################
	# Network Connections
	######################
	write-host `n"Network Connections..." -background "white" -foreground "Darkblue"
	$ldapCnt = Invoke-Command -ComputerName $computerName -ScriptBlock {(netstat -an | findstr ":389").count}
	$objDC  = New-Object psobject -Property @{Item = "LDAP Connections";Value = $ldapCnt.ToString();Description = "LDAP Connection Count on Port 389";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
	$ldapsCnt = Invoke-Command -ComputerName $computerName -ScriptBlock {(netstat -an | findstr ":636").count}
	$objDC  = New-Object psobject -Property @{Item = "LDAPs Connections";Value = $ldapsCnt.ToString();Description = "LDAPs Connection Count on Port 636";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
	$GCCnt = Invoke-Command -ComputerName $computerName -ScriptBlock {(netstat -an | findstr ":3268").count}
	$objDC  = New-Object psobject -Property @{Item = "GC Connections";Value = $GCCnt.ToString();Description = "Global Catalog Connection Count on Port 3268";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
	$GCsCnt = Invoke-Command -ComputerName $computerName -ScriptBlock {(netstat -an | findstr ":3269").count}
	$objDC  = New-Object psobject -Property @{Item = "GC SSL Connections";Value = $GCsCnt.ToString();Description = "Global Catalog ssl Connection on Count Port 3269";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
	$DNSCnt = Invoke-Command -ComputerName $computerName -ScriptBlock {(netstat -an | findstr ":53").count}
	$objDC  = New-Object psobject -Property @{Item = "DNS Connections";Value = $DNSCnt.ToString();Description = "DNS Connection Count on Port 53";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
	$KRBCnt = Invoke-Command -ComputerName $computerName -ScriptBlock {(netstat -an | findstr ":88").count}
	$objDC  = New-Object psobject -Property @{Item = "Kerberos Connections";Value = $KRBCnt.ToString();Description = "Kerberos Connection Count on Port 88";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
	$KRBPwdCnt = Invoke-Command -ComputerName $computerName -ScriptBlock {(netstat -an | findstr ":464").count}
	$objDC  = New-Object psobject -Property @{Item = "Kerberos PWD Connections";Value = $KRBCnt.ToString();Description = "Kerberos Connection Count on Port 464";s = "green";Date = $Date.ToString("s")};$collDC += $objDC

	$SMBCnt = Invoke-Command -ComputerName $computerName -ScriptBlock {(netstat -an | findstr ":445").count}
	$objDC  = New-Object psobject -Property @{Item = "SMB Connections";Value = $SMBCnt.ToString();Description = "SMB Connection Count on Port 445";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
	$RPCCnt = Invoke-Command -ComputerName $computerName -ScriptBlock {(netstat -an | findstr ":135").count}
	$objDC  = New-Object psobject -Property @{Item = "RPC Connections";Value = $RPCCnt.ToString();Description = "RPC Connection Count on Port 135";s = "green";Date = $Date.ToString("s")};$collDC += $objDC

	write-Host `n"Memory..." -background "white" -foreground "Darkblue"
	$TotalPhysicalMemory = invoke-command -ComputerName $computerName -ScriptBlock {(systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim()}
	$objDC  = New-Object psobject -Property @{Item = "Total Physical Memory";Value = $TotalPhysicalMemory.ToString();Description = "Total Physical Memory";s = "green";Date = $Date.ToString("s")};$collDC += $objDC

	$AvailablePhysicalMemory = invoke-command -ComputerName $computerName -ScriptBlock {(systeminfo | Select-String 'Available Physical Memory:').ToString().Split(':')[1].Trim()}
	$objDC  = New-Object psobject -Property @{Item = "Available Physical Memory";Value = $AvailablePhysicalMemory.ToString();Description = "Available Physical Memory";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
}
# Virtual Memory: Max Size:  18,815 MB
# Virtual Memory: Available: 11,929 MB
# Virtual Memory: In Use:    6,886 MB


write-host `n"Certificates..." -background "white" -foreground "Darkblue"
If($winRM){
	$MachineCerts = invoke-command -ComputerName $computerName -ScriptBlock {Get-ChildItem -Path cert:\LocalMachine\My -Recurse | format-table -auto -property Subject,Issuer,NotAfter,EnhancedKeyUsageList}
	$MachineCerts
	$MachineCerts = invoke-command -ComputerName $computerName -ScriptBlock {Get-ChildItem -Path cert:\LocalMachine\My -Recurse | select-object -property Subject,Issuer,NotAfter,EnhancedKeyUsageList}
	#foreach($Cert in $MachineCerts){$objDC  = New-Object psobject -Property @{Item = "Issuer:"+ $Cert.Issuer;Value = "NotAfter:"+$cert.NotAfter;Description = "Subject:"+$Cert.Subject;s = "green";Date = $Date.ToString("s")};$collDC += $objDC}
	foreach($Cert in $MachineCerts){
        $Today = get-date
        If ($cert.NotAfter -lt $today){$Status = "yellow"}else{$status = "green"}
        $objDC  = New-Object psobject -Property @{Item = "Issuer:"+ $Cert.Issuer;Value = "NotAfter:"+$cert.NotAfter;Description = "Subject:"+$Cert.Subject;s = $Status}
        $collDC += $objDC
    }
	$EncryptString = invoke-command -ComputerName $computerName -scriptblock {manage-bde -status}
	foreach($line in $EncryptString){If(($line -like '*volume*:*')-or($line -like '*conversion*')){If($line -like "*Decrypted*"){$Encrypted = "**Warning Not Encrypted"};write-host $line;$thebody = $thebody + "<br>"+$line}}
	write-host $Encrypted
}
else{Write-host WinRM Failure - Unable to Enumerate Certificates or Disk Encryption}

Write-Host `nReplication... -background "white" -foreground "Darkblue"
if($winRM){
	$RepQueue = winrs -r:$computerName repadmin /queue
	$RepQueue
	foreach($line in $RepQueue){if($line -Like "*Queue contains*"){$value = $line.split(" ")[2];if($value -eq 0){$status="green"}else{$status = "yellow"}}}
	$objDC  = New-Object psobject -Property @{Item = "Replication";Value = $Value;Description = "Replication Queue Status";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
}
Write-Host `nGlobal Catalog Status... -background "white" -foreground "Darkblue"
if($winRM){
	$GC = winrs -r:$computerName repadmin /options
	write-host $GC
	If($GC -like '*IS_GC*'){write-host Is a GC: $True;$Value = $True;$Status = "green"}else{write-host Is a GC: $False;$Value = $False;$Status = "yellow"}
	$objDC  = New-Object psobject -Property @{Item = "IS_GC";Value = $Value;Description = "Global Catalog Status";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
}
# Patch OU
Write-Host `nGPO OU... -background "white" -foreground "Darkblue"
	$OU = get-adobject -filter {((objectClass -like "computer")-and(name -like $HostdcName))} -SearchBase "DC=za,DC=dov" -Properties DistinguishedName -server "za.dov:3268"
	write-host $OU
	If($OU -like '*Monday*'){Write-Host Monday;$Value = "Monday";$Status = "green"}
	elseIf($OU -like '*Wednesday*'){Write-Host Wednesday;$Value = "Wednesday";$Status = "green"}
	elseIf($OU -like '*Friday*'){Write-Host Friday;$Value = "Friday";$Status = "green"}
	else{Write-Host **Warning Not in GPO OU;$Value = "";$Status = "yellow"}
	$objDC  = New-Object psobject -Property @{Item = "OU";Value = $Value;Description = "Patching OU";s = $status;Date = $Date.ToString("s")};$collDC += $objDC

write-host `nFile System... -background "white" -foreground "Darkblue"
if($winRM){
	$Files = get-childitem \\$computerName\c$ -File
	write-host File Count on C Drive: $Files.count
	If($Files.count -gt 1){write-host "**warning extra files found on root of C";$value = $Files.count;$Status = "yellow"}else{$Value = $files.count;$Status = "green"}
	$objDC  = New-Object psobject -Property @{Item = "File Count";Value = $Value;Description = "Files in Root C:\";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
}

write-host `n'DNS EnableGlobalNamesSupport...' -background "white" -foreground "Darkblue"
Try{$EnableGNS = reg query "\\$computerName\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v "EnableGlobalNamesSupport"
if ($EnableGNS -like "*0x1*"){write-host Enabled;$GNS = "Enabled";$status = "green"}else{write-host ** Not Enabled;$GNS = "**Not Enabled";$status = "yellow"}
$objDC  = New-Object psobject -Property @{Item = "EnableGlobalNameSupport";Value = $GNS;Description = "Global Name Support";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
}
Catch{
	$objDC  = New-Object psobject -Property @{Item = "EnableGlobalNameSupport";Value = $error[0].Exception.Message;Description = "Global Name Support";s = "red";Date = $Date.ToString("s")};$collDC += $objDC
}

write-host `n'UpTime...' -background "white" -foreground "Darkblue"
try{
	$wmi=Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computerName
	$boottime=$wmi.ConvertToDateTime($wmi.LastBootUpTime)
	write-host "Last boot...$boottime"$boottime -background "white" -foreground "Darkblue"
	$objDC  = New-Object psobject -Property @{Item = "Last_Boot";Value = $boottime.ToString();Description = "Last Boot Time";s = "green";Date = $Date.ToString("s")};$collDC += $objDC

	[TimeSpan]$uptime=New-TimeSpan $boottime $(get-date)
    #$theUpTime = (Get-Date) - [Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem -ComputerName $computerName).LastBootUpTime)
    #if(($theuptime.Days -gt 60)-and($SinceInstall.Days -gt 60 )){$Status = "Yellow"}Else{$Status = "Green"}

	Write-host "`nUptime... "$uptime.days "Days" $uptime.hours "Hours" $uptime.minutes "Minutes" $uptime.seconds "Seconds" -background "white" -foreground "Darkblue"
	$stringUptime = $uptime # +  $uptime.minutes  "Minutes"  $uptime.seconds'
    if($uptime.Days -gt 60){$Status = "yellow"}else{$status = "green"}
	$objDC  = New-Object psobject -Property @{Item = "Uptime";Value = $stringUptime.ToString();Description = "Days.Hours:Minuts:Seconds.Milliseconds";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
    }
    Catch{
        write-Host  $_.Exception.Message
    }
# CRL Status
write-host `n'CRL Validity Extension...' -background "white" -foreground "Darkblue"
if($winRM){
	Try{
		$CRLValidityExtension = Invoke-Command -ComputerName $computerName {Get-ItemProperty -Path HKLM:System\CurrentControlSet\Services\KDC -name CRLValidityExtensionPeriod | Select-Object CRLValidityExtensionPeriod}
		write-host "`nCRL Validity Period : " $CRLValidityExtension.CRLValidityExtensionPeriod
		if($CRLValidityExtension.CRLValidityExtensionPeriod -eq 72){$status = "green"}else{$status = "yellow"}
		$objDC  = New-Object psobject -Property @{Item = "CRLValidityExtension";Value = $CRLValidityExtension.CRLValidityExtensionPeriod;Description = "How long an Expired CRL is good for";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
		}
		Catch{
			write-Host  $_.Exception.Message
		}
		Write-Host "`nCRLs ((Name Contains B1) and (File Size > 17Mb))" -background "white" -foreground "Darkblue"
		Try{
		$theTable = get-childitem \\$computerName\c$\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content | Where-Object {($_.Length -gt 15000000)}| Select-Object LastWriteTime, Length, Directory, Name 
		$theTable | Format-Table -AutoSize
		#get-childitem \\vhafar3dc1\c$\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content | where {($_.LastWriteTime.Date -eq (get-date).Date)-and($_.Length -gt 29000000)}| select Name, LastWriteTime, Length | Format-Table -AutoSize
		}
		Catch{
			write-Host  $_.Exception.Message
		}
}
else{
	#write-host `n'CRL Validity Extension...' -background "white" -foreground "Darkblue"
	$CRLValidityExtension = reg query "\\$computerName\HKLM\SYSTEM\CurrentControlSet\Services\KDC" /v "CRLValidityExtensionPeriod"
	if ($CRLValidityExtension -like "*0x48*"){write-host $CRLValidityExtension;$status = "green"}else{write-host ** $CRLValidityExtension;$status = "yellow"}
	$objDC  = New-Object psobject -Property @{Item = "CRLValidityExtension";Value = "72";Description = "CRL Validity Extension Period Hours";s = $status;Date = $Date.ToString("s")};$collDC += $objDC

}
# Pre-fetch
Write-Host "`nCRL Prefetch Task" -background "white" -foreground "Darkblue"
$proc_header ="HostName","TaskName","NextRunTime","Status","LogonMode","LastRunTime","LastResult","Author","TaskToRun","StartIn","Comment","ScheduledTaskState","Idle Time","Power Management","Run As User","DeleteTaskIfNotRescheduled","Stop Task If Runs X Hours and X Mins","Schedule","ScheduleType","StartTime","StartDate","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running"
$tasks =  schtasks /query /s $computerName /tn PrefetchCRL /fo csv /v | ConvertFrom-CSV -header $proc_header
$tasks | where-object {$_.TaskName -eq "\PrefetchCRL"} | select-object HostName,TaskName,Status,NextRunTime,LastRunTime,LastResult | format-Table
$CRLTask = $tasks | where-object {$_.TaskName -eq "\PrefetchCRL"} | select-object HostName,TaskName,Status,NextRunTime,LastRunTime,LastResult
if($CRLTask.Status -eq "Ready"){$status = "green"}else{$status = "yellow"}
if($CRLTask.LastResult -eq 0){$Description = "Task Last Run Time"}else{$status = "red";$Description = $CRLTask.LastResult;write-host *Warning Task Error}
$objDC  = New-Object psobject -Property @{Item = "CRLPrefetch Task Last Run";Value = $CRLTask.LastRunTime;Description = $Description;s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$objDC  = New-Object psobject -Property @{Item = "CRLPrefetch Task Next Run";Value = $CRLTask.NextRunTime;Description = "Task Next Run Time";s = $status;Date = $Date.ToString("s")};$collDC += $objDC

# Services
Write-Host `nServices... -background "white" -foreground "Darkblue"
# Replication
Write-Host `nReplication... -background "white" -foreground "Darkblue"
Try{
$theService = get-wmiobject win32_Service -computername $computerName | select-object name, DisplayName,Description, state | where-object {$_.name -eq "DFSR"}
"{0} ({1}) is {2} - {3}" -f ($theService.DisplayName),($theService.name),($theService.state),($theService.Description.substring(0,80))| Write-Output 
}
Catch{
    write-Host  $_.Exception.Message
}
Write-Host `nDNS... -background "white" -foreground "Darkblue"
Try{
$theService = get-wmiobject win32_Service -computername $computerName | select-object name, DisplayName,Description, state | where-object {$_.name -eq "DNS"}
"`n{0} service ({1}) is {2} - {3}" -f ($theService.DisplayName),($theService.name),($theService.state),($theService.Description.substring(0,97))| Write-Output 
}
Catch{
    write-Host  $_.Exception.Message
}
Try{
$theService = get-wmiobject win32_Service -computername $computerName | select-object name, DisplayName,Description, state | where-object {$_.name -eq "Dnscache"}
"{0} service ({1}) is {2} - {3}" -f ($theService.DisplayName),($theService.name),($theService.state),($theService.Description.substring(34,74))| Write-Output 
Write-host `nNSLookup... -background "white" -foreground "Darkblue"

Try{
	$theService = get-wmiobject win32_Service -computername $computerName | select-object name, DisplayName,Description, state | where-object {$_.name -eq "Netlogon"}
	Write-host $theService.DisplayName $theService.name $theService.state
	If($theService.state -Like "*Running*"){$Status = "green"}else{$status = "yellow"}
	$objDC  = New-Object psobject -Property @{Item = "Netlogon";Value = $theService.state;Description = "Client Auth - Authenticates/registers/locates DCs";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC
	}
Catch{
		write-Host  $_.Exception.Message
		$objDC  = New-Object psobject -Property @{Item = "Netlogon";Value = $theService.state;Description = "Client Auth - Authenticates/registers/locates DCs";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC
}
Try{
		$theService = get-wmiobject win32_Service -computername $computerName | select-object name, DisplayName,Description, state | where-object {$_.name -eq "NimbusWatcherService"}
		Write-host $theService.DisplayName $theService.name $theService.state
		If($theService.state -Like "*Running*"){$Status = "green"}else{$status = "yellow"}
		$objDC  = New-Object psobject -Property @{Item = "CA UIM Nimbus Robot Watcher";Value = $theService.state;Description = "Enterprise Command Center (ECC) monitoring agent";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC
}
Catch{
			write-Host  $_.Exception.Message
			$objDC  = New-Object psobject -Property @{Item = "CA UIM Nimbus Robot Watcher";Value = $theService.state;Description = "Enterprise Command Center (ECC) monitoring agent";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC
}

Try{
		$theService = get-wmiobject win32_Service -computername $computerName | select-object name, DisplayName,Description, state | where-object {$_.name -eq "BESClent"}
		Write-host $theService.DisplayName $theService.name $theService.state
		If($theService.state -Like "*Running*"){
            $Status = "yellow"
            $objDC  = New-Object psobject -Property @{Item = "BESClient";Value = $theService.state;Description = "BigFix";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC
        }
        else{$status = "green"}
		
}
Catch{
			write-Host  $_.Exception.Message
			#$objDC  = New-Object psobject -Property @{Item = "BESClietn";Value = $theService.state;Description = "BigFix";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC
}

########################
# DNS Lookups
########################
Nslookup crl.pki.za.dov $computerName
}
Catch{
    write-Host  $_.Exception.Message
}
#######################
# DNS A and PTR Records
#######################
$Arecord = Resolve-DnsName $computerName
If ($Arecord.Type -eq 'A'){$Status='green'}else{$status='yellow'}
$objDC  = New-Object psobject -Property @{Item = "A Record";Value = $Arecord.Name;Description = "DNS A Record";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC

$PTRrecord = Resolve-DnsName $IPAddress
If ($PTRrecord.Type -eq 'PTR'){$Status ='green'}else{$status ='yellow'}
$objDC  = New-Object psobject -Property @{Item = "PTR Record";Value = $PTRrecord.Name;Description = "DNS PTR Record";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC

#####################
#Quest Change Auditor
#####################
if(WinRM){
    Try{
        $QuestCA = Get-Service -Displayname "Quest Change*" -computername $computerName -ErrorAction stop
        $Status = $QuestCA.Status
        If($QuestCA.Status -eq "Running"){
            $objDC  = New-Object psobject -Property @{Item = "Change Auditor";Value = $QuestCA.Status;Description = $QuestCA.DisplayName;s = "green";Date = $Date.ToString("s")};$collDC += $objDC
        }
        else{
            $objDC  = New-Object psobject -Property @{Item = "Change Auditor";Value = $QuestCA.Status;Description = $QuestCA.DisplayName;s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC
        }
    }
    catch{$objDC  = New-Object psobject -Property @{Item = "Change Auditor";Value = "NotFound";Description = "Quest Change Auditor";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC
    }
<#else{
    # add code for 445 servcie NPSrvHost
    $objDC = New-Object psobject -Property @{Item = "Change Auditor";Value = "NotFound";Description = "Add code for 445 Quest Change Auditor";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC
    }
    #>
}

# Disks Status
Write-Host `nDisks... -background "white" -foreground "Darkblue"
try{
$disk = ([wmi]"\\$computerName\root\cimv2:Win32_logicalDisk.DeviceID='c:'")
}
Catch{
    write-Host  $_.Exception.Message
}
If ($disk.FreeSpace/1GB -lt 2) {Write-Host Alert Low Disk Space -background "Red" }
Try{
"C: has {0:#.0} GB free of {1:#.0} GB Total" -f ($disk.FreeSpace/1GB),($disk.Size/1GB) | write-output
if(($disk.FreeSpace/1GB) -gt 50){$Status = "green"}else{$status = "yellow"}
$objDC  = New-Object psobject -Property @{Item = "C:";Value = [math]::Truncate($disk.FreeSpace/1GB);Description = "Free Space on C";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$disk = ([wmi]"\\$computerName\root\cimv2:Win32_logicalDisk.DeviceID='g:'")
"G: has {0:#.0} GB free of {1:#.0} GB Total" -f ($disk.FreeSpace/1GB),($disk.Size/1GB) | write-output
if(($disk.FreeSpace/1GB) -gt 50){$Status = "green"}else{$status = "yellow"}
$objDC  = New-Object psobject -Property @{Item = "G:";Value = ($disk.FreeSpace/1GB);Description = "Free Space on G";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
$disk = ([wmi]"\\$computerName\root\cimv2:Win32_logicalDisk.DeviceID='L:'")
"L: has {0:#.0} GB free of {1:#.0} GB Total" -f ($disk.FreeSpace/1GB),($disk.Size/1GB) | write-output
if(($disk.FreeSpace/1GB) -gt 50){$Status = "green"}else{$status = "yellow"}
$objDC  = New-Object psobject -Property @{Item = "L:";Value = ($disk.FreeSpace/1GB);Description = "Free Space on L";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
}
Catch{
    write-Host  $_.Exception.Message
}
######################
## Remote Managment
#
if($CompBIOS.BiosManufacturer -eq "Dell Inc."){
	$iDRAC = "iDRAC-"+$hostDCname+".rmoc.za.dov"
	Test-Connection $iDRAC
	if(Test-Connection $iDRAC -q){$status = "green"}
	else{$status = "yellow"}
	$Value = "http://"+$iDRAC;$Description = "iDRAC";$cloud = $false;write-host "Remote Management iDRAC" $iDRAC
}
elseif($CompBIOS.BiosManufacturer -eq "HPE"){
$Value = "http://iLO";$Description = "iLO"
}
else{
	############################
	## Check for Cloud Server   
	#
	if($computerName.Substring(0,4) -eq "VAC2"){$Value = "";$Description = "Azure Portal";$cloud = $true;Write-host "Remote Management Azure Portal";$Value = "https://Azure.portal.us"}
	elseif($computerName.Substring(0,4) -eq "VAC3"){$Value = "";$Description = "Msft Azure Public Cloud";$cloud = $true;Write-host "Remote Management Azure Public Portal";$Value = "https://???"}
	elseif($computerName.Substring(0,4) -eq "VAC1"){$Value = "";$Description = "Amazon Web Services";$cloud = $true;Write-host "Remote Management AWS Portal";$Value = "https://core-gov-internal.signin.amazonaws-us-gov.com/console"}
	else{$cloud = $false}
	If($cloud){$status = "green"}
}
$objDC  = New-Object psobject -Property @{Item = "Remote Managment";Value = $Value;Description = $Description;s = $status;Date = $Date.ToString("s")};$collDC += $objDC

If($CompBIOS.BiosManufacturer -eq "Dell Inc."){
	# Dell Open Manage Service
	write-host `n'Open Manage Service...' -background "white" -foreground "Darkblue"
	if($winRM){
		$OMEService = Get-Service omsad -computername $computerName
		$OMEStatus = $OMEService.Name + " " + $OMEService.Status + " " + $OMEService.Displayname
		write-host $OMEStatus
		If($OMEStatus -like '*Running*'){	$Value = $OMEStatus;$Status = "yellow"}
		Else{$value = $OMEStatus;$Status = "green"}
		$objDC  = New-Object psobject -Property @{Item = "OME";Value = $Value;Description = "Open Manage Service Uninstalled";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
	}
	else{
		Try{
			$theService = get-wmiobject win32_Service -computername $computerName | select-object name, DisplayName,Description, state | where-object {$_.name -eq "omsad"}
			"{0} ({1}) is {2} - {3}" -f ($theService.DisplayName),($theService.name),($theService.state),($theService.Description.substring(0,80))| Write-Output 
			$objDC  = New-Object psobject -Property @{Item = "OME";Value = $theService.state;Description = "Open Manage Service Uninstalled";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC
			}
			Catch{
				write-Host  $_.Exception.Message
				$objDC  = New-Object psobject -Property @{Item = "OME";Value = "Not Found";Description = "Open Manage Service";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
			}
	}
}
###########################
#Splunk Universal Forwarder
write-host Finding Splunk...
$mySplunk = "";
Try{
	$SplunkPath = Invoke-Command -ComputerName $computerName {Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SplunkForwarder.remove -Name ImagePath -ErrorAction SilentlyContinue}
	$Connect = "WinRM (5985)"
	$FilePath = $SplunkPath.ImagePath
	$FilePath = $FilePath.Replace('"','')
	# Need to fix this when it cannot find the services.
	$file = Get-Item ('\\' + $computerName + '\' + $FilePath.Replace(':','$'))  -ErrorAction SilentlyContinue
	$mySplunk = $file.VersionInfo.ProductVersion
	$objDC  = New-Object psobject -Property @{Item = "Splunk";Value = $mySplunk;Description = "Splunk Service (via 5985)";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
	}
	Catch { 
		write-host "CATCH Splunk No WinRM (5985) falling back to Microsoft-ds Port (445)"
		$Connect = "Microsoft-ds (445)"
		$mySplunk = ""
		# Remotely
		$mySplunk = Get-WmiObject Win32_Product -ComputerName $computerName | where-object {$_.name -like '*UniversalForwarder*'}
		$mySplunk = $mySplunk.Version
		if($mySplunk.split(".")[0] -gt 8){$status = 'green'}else{$status='yellow'}
		$objDC  = New-Object psobject -Property @{Item = "Splunk";Value = $mySplunk;Description = "Splunk Service (via 445)";s = $status;Date = $Date.ToString("s")};$collDC += $objDC

	}

Write-Host $mySplunk
# End Splunk
############

#SCCM *************************
write-host Finding SCCM...	
try{
	$SCCMPath = Invoke-Command -ComputerName $computerName {Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CcmExec -Name ImagePath -ErrorAction SilentlyContinue}
	$Connect = "WinRM (5985)"
	$FilePath = $SCCMPath.ImagePath
	$FilePath = $FilePath.Replace('"','')
	$file = Get-Item ('\\' + $computerName + '\' + $FilePath.Replace(':','$'))
	$mySCCM = $file.VersionInfo.FileVersion.split(" ")[0]
	$objDC  = New-Object psobject -Property @{Item = "SCCM";Value = $mySCCM;Description = "SCCM Service (via 5985)";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
}
Catch{ 
	try{
	write-host "CATCH SCCM no WINRM falling back to Microsoft-ds Port 445"
	$Connect = "Microsoft-ds (445)"
	$mySCCM =""
	# Remotely
	$mySCCM = (Get-WMIObject -ComputerName $computerName -Namespace root\ccm -Class SMS_Client).ClientVersion
	if($mySCCM -eq ""){$status = "yellow"}{$status = "green"}
	$objDC  = New-Object psobject -Property @{Item = "SCCM";Value = $mySCCM;Description = "SCCM Service (via 445)";s = $status;Date = $Date.ToString("s")};$collDC += $objDC
	}
	Catch{
		$mySCCM = "Not Found"
	$objDC  = New-Object psobject -Property @{Item = "SCCM";Value = "Not Found";Description = "SCCM Service";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC

	}
	<#
	$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $computerName)
	$regKey= $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\services\\CcmExec",$true)
	$mySCCM = $regkey.GetValue("ImagePath")
	write-host $mySCCM
	$mySCCM = $mySCCM.split("\")[-1]
	#>
}
Write-Host SCCM: $mySCCM 
# End SCCM
############

#SCCM SiteCode **************** 
Try{$SiteCode = $([WmiClass]"\\$computerName\ROOT\ccm:SMS_Client").getassignedsite() | Select-Object sSiteCode
	$SiteCode = $SiteCode.sSiteCode
	write-host $SiteCode
	$objDC  = New-Object psobject -Property @{Item = "SiteCode";Value = $SiteCode;Description = "SCCM Site Code";s = "green";Date = $Date.ToString("s")};$collDC += $objDC

}
catch{
	$_.error;$siteCode = ""
	$objDC  = New-Object psobject -Property @{Item = "SiteCode";Value = $SiteCode;Description = "SCCM Site Code";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC
}
# End SiteCode
##############

###################
# DeviceTagging
##################
Try{
	$DeviceTag = Invoke-Command -ComputerName $computerName {Get-ItemPropertyValue -Path "HKLM:\\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" -Name 'Group'}
	if($DeviceTag -eq 'AD_DomainController'){$Status='green'}else{$Status ='yellow'}
	$objDC  = New-Object psobject -Property @{Item = "Device Tag";Value = $DeviceTag.ToString();Description = "MDE Tag";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC
}
Catch{
	$objDC  = New-Object psobject -Property @{Item = "Device Tag";Value = $DeviceTag.ToString();Description = "MDE Tag";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC
}

###################
# Time Source
##################
Try{
	$TimeSource = Invoke-Command -ComputerName $computerName {Get-ItemPropertyValue -Path "HKLM:\\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -name Type}
	if($TimeSource -eq 'NT5DS'){$Status='green'}else{$Status ='yellow'}
	$objDC  = New-Object psobject -Property @{Item = "Time Source";Value = $TimeSource.ToString();Description = "Time Source";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC
}
Catch{
	$objDC  = New-Object psobject -Property @{Item = "Time Source";Value = $TimeSource.ToString();Description = "Time Source";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC
}

# Get-ItemProperty -Path "HKLM:\\SYSTEM\CurrentControlSet\Services\SNMP\Parameters"
# Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters
# Get-Item -Path "HKLM:\\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"


##############
# SNMP Service
##############
write-host Finding SNMP...	
Try{
$SNMPService = Get-Service -ComputerName $computerName SNMP
write-host $SNMPService.Status	
$objDC  = New-Object psobject -Property @{Item = "SNMP";Value = $SNMPService.Status;Description = "SNMP Service";s = "green";Date = $Date.ToString("s")};$collDC += $objDC

}
Catch{
	$objDC  = New-Object psobject -Property @{Item = "SNMP";Value = $SNMPService.Status;Description = "SNMP Service";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC

}
#######################
# SNMP ValidCommunities
#######################
Try{
	$mySNMPString = Invoke-Command -ComputerName $computerName {Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities}
	write-host $mySNMPString.Property

	# $SNMP = Invoke-Command -ComputerName $computerName {Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters}
	# # foreach($key in $SNMP){$Key}
	# foreach($key in $SNMP){Get-ItemProptery $Key.Name}

	# $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
	# $regKey= $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\services\\SNMP\\Parameters\\ValidCommunities",$true)
	# $regkey.GetValueNames() | ForEach-Object {$mySNMPString = $mySNMPString + $_ + "(" + $regkey.getvalue($_) + ")" + " "}
	# write-host ValidCommunities: $mySNMPString
	$objDC  = New-Object psobject -Property @{Item = "SNMP String";Value = $mySNMPString.Property.split(" ")[0];Description = "SNMP String";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
}
catch{
	$objDC  = New-Object psobject -Property @{Item = "SNMP String";Value = "";Description = "SNMP String";s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC

}
# End SNMP
##########

#extension Attribute 12
$Array = $computerName.split(".")
$SHostName = $Array[0]
$Domain = ($array[1..($array.Length -1)] -join ".")
$CompObj = get-adcomputer -filter {Name -eq $SHostName} -Server $Domain -properties * 
$exAt12 = $CompObj.ExtensionAttribute12
if($exAt12 -eq ""){
	$objDC  = New-Object psobject -Property @{Item = "ExtensionAttribute12";Value = $exAt12;Description = "ExtensionAttribute12";s = "green";Date = $Date.ToString("s")};$collDC += $objDC

}
else{
	$objDC  = New-Object psobject -Property @{Item = "ExtensionAttribute12";Value = $exAt12;Description = "ExtensionAttribute12";s = "green";Date = $Date.ToString("s")};$collDC += $objDC
}
write-host $exAt12

######################################
# OIT ITOPS SD CIS AD Defender Clients
######################################
$DefenderClientsGroup = "CN=OIT ITOPS SD CIS AD Defender Clients,OU=Security,OU=Management Groups,DC=za,DC=dov"
$inDefenderClients = $False
$Status = "yellow"
$EndDollarDCFlatName = $DCFlatName+"$"
$groups = (get-adcomputer -filter {samAccountName -eq $EndDollarDCFlatName } -properties MemberOf -server za.dov:3268 | Select-object MemberOf).MemberOf
foreach ($group in $groups){
	if($group -eq $DefenderClientsGroup){$inDefenderClients = $True;$Status = "green"}
}
$objDC  = New-Object psobject -Property @{Item = "Defender Clients Group";Value = $inDefenderClients;Description = "OIT ITOPS SD CIS AD Defender Clients";s = $Status;Date = $Date.ToString("s")};$collDC += $objDC

# End Defender Clients Group
############################

###############
## .dit size   
#
$Description = "Directory Information Tree"
If (winRM){
	$ditFile = "\\"+$computerName+"\G$\Windows\NTDS\ntds.dit"
	$ditSize = ((Get-item $ditFile).length/1KB)
	$objDC  = New-Object psobject -Property @{Item = "NTDS.dit Size";Value = $ditSize;Description = $Description;s = "green";Date = $Date.ToString("s")};$collDC += $objDC
}
else{$objDC  = New-Object psobject -Property @{Item = "NTDS.dit Size";Value = "WinRM_Failure";Description = $Description;s = "yellow";Date = $Date.ToString("s")};$collDC += $objDC}
if($time.ispresent){

 <# $PDCemulator = (Get-ADDomain).pdcemulator
  $computerNameTime = icm $computerName {get-date}
  $PDCTime = icm $PDCemulator {get-date}
  Write-host PDC: $PDCemulater $PDCTime
  Write-host DC : $computerName $computerNameTime
  #>
  # w32tm /query /status /computer:$computerName 
  Try{
    $w32tm = w32tm /monitor /computers:$computerName /nowarn; $w32tm | foreach-object {write-host $_ ;If($_ -like '*ICMP:*'){$OptimalTimeSync = $_.Substring(10)}}
    If($OptimalTimeSync -gt "100000ms"){ write-host *Warning Time Sync is $OptimalTimeSync -foregroundcolor "Yellow"} #100000ms = 2 minutes
    #write-host $OptimalTimeSync  
  }
  Catch{write-Host  $_.Exception.Message}

  Write-host `nChecking Net Time...
  Net time \\$computerName
}
if($smartcard.ispresent){

	#Smart Card Logon Events
	write-host Smart Card Logon Events... -background "white" -foreground "Darkblue"
	Try{
	$events = Get-WinEvent -computername $computerName -FilterHashtable @{ logname = "System"; ID = "21"; StartTime = [datetime]::today} -ErrorAction SilentlyContinue
	Write-host $events.count [Event 21 failed smart card logons today]`n
	$events
	}
	Catch{
	write-Host  $_.Exception.Message
	}
	
	Try{
	$events = Get-WinEvent -computername $computerName -FilterHashtable @{ logname = "System"; ID = "29"; StartTime = [datetime]::today} -ErrorAction SilentlyContinue     
	Write-host $events.count [Event 29 KDC Smart card events today]`n
	$events.Message
	}
	Catch{
	write-Host  $_.Exception.Message
	}
	Try{
	$events = Get-WinEvent -computername $computerName -MaxEvents 10 -FilterHashtable @{ Providername = "Microsoft-Windows-CAPI2"; Level= 2; ID = "11"; StartTime = [datetime]::today} # -ErrorAction SilentlyContinue     
	Write-host $events.count [Event 11 CAPI2 events today]`n
	$events
	}
	Catch{
	write-Host  $_.Exception.Message
	}

}

$collDC | Select-Object Item, Value, Description, s | Format-Table

#ShowRepl
if ($ShowRepl.IsPresent){Start-Process cmd.exe "/K `"winrs -r:`"$computerName repadmin /showrepl"}

#DCDiag
if ($computerNameDiag.IsPresent){
	Write-Host `nDC Diagnostics...`n -background "white" -foreground "Darkblue"
	Start-Process cmd.exe "/K `"winrs -r:`"$computerName dcdiag"
}
#RDP
#iLO
		<#
	
			write-host `nGetting Timezone... -background "white" -foreground "Darkblue"
			$thebody = $thebody + "<br><br><u>Timezone</u><br>"
			$timeZone=Get-WmiObject -Class win32_timezone -ComputerName $computerName
			$timeZone.Caption
			$thebody = $thebody + "<b>"+$timeZone.Caption+"</b>"
		
			$IsBK = $False
			write-host `nBigkahunas... -background "white" -foreground "Darkblue"
			$thebody = $thebody + "<br><br><u>Bigkahunas</u><br>"
			$BKs = "bigkahunas."+$domainDC  
			$theBK = nslookup $BKs
			foreach($Line in $theBK){$lnCnt++;If(($Line -Like '*Server:*')-or($Line -Like '*Address:*')){}else{If($Line -like '*'+$IPAddress+'*'){$IsBK = $True;write-host $Line;$thebody=$thebody + $Line}else{write-host $Line;$thebody=$thebody + $Line}}}
			Write-host Is Bigkahuna: $IsBK
			$thebody=$thebody + "<br>Is Bigkahuna: <b>"+ $IsBK+"</b>"
				
			$Firmware = invoke-command -computername $computerName -scriptblock {omreport system version}
				$BiosVersion = $Firmware | Select-String 'BIOS' -Context 0,1 | ForEach-Object {$_.Context.PostContext.split(": ")[3]}
			If($BiosVersion -eq "2.8.0"){write-host "`nBIOS: " $BiosVersion;$thebody = $thebody + "<br><br>BIOS: <b>$BiosVersion"+ "</b>"}
			Else{write-host "`nBIOS: *Warning* " $BiosVersion;$thebody = $thebody + "<br><br>BIOS: <b>*Warning* $BiosVersion"+ "</b>"}
		
				$iDRACVersion = $Firmware | Select-String 'iDRAC' -Context 0,1 | ForEach-Object {$_.Context.PostContext.split(": ")[3]}
			 If($iDRACVersion -eq "2.63.60.62"){write-host "`niDRAC: " $iDRACVersion;$thebody = $thebody + "<br>iDRAC: <b>$iDRACVersion" + "</b>"}
			Else{write-host "`niDRAC: *Warning* " $iDRACVersion;$thebody = $thebody + "<br>iDRAC: *Warning* $iDRACVersion"+ "</b>"}
		
				$StorageFirmwareVersion = $Firmware | Select-String 'PERC' -Context 0,1 | ForEach-Object {$_.Context.PostContext.split(": ")[3]}
			If($StorageFirmwareVersion -eq "21.3.5-0002"){write-host "`nSAS-RAID Firmware: " $StorageFirmwareVersion;$thebody = $thebody + "<br>SAS-RAID Firmware: <b>$StorageFirmwareVersion" + "</b>"}
			Else{write-host "`nSAS-RAID Firmware: *Warning* " $StorageFirmwareVersion;$thebody = $thebody + "<br>SAS-RAID Firmware: *Warning* $StorageFirmwareVersion"+ "</b>"}
		
				$OSVersion = $Firmware | Select-String 'Microsoft' -Context 0,1 | ForEach-Object {$_.Context.PostContext.split(": ")[4]}
			If ($OSVersion -eq "10.0"){write-host "`nOS: " $OSVersion;$thebody = $thebody + "<br>OS Version: <b>$OSVersion" + "</b>"}
			Else {write-host "`nOS: *Warning* " $OSVersion;$thebody = $thebody + "<br>OS Version: <b>*Warning* $OSVersion"+ "</b>"}
		
				$Broadcom = Get-WmiObject -computer $computerName win32_pnpsigneddriver | Where-Object { $_.Description -like "*Broadcom*" }  | Select-Object -First 1 FriendlyName, Description , Manufacturer, driverdate, driverversion
			If ($Broadcom.driverversion -eq "214.0.0.1"){write-host "`nNIC: "$Broadcom.Description $Broadcom.driverversion;$thebody = $thebody + "<br>NIC: " + $Broadcom.Description + " <b>" + $Broadcom.driverversion + "</b>"}
			Else {write-host "`nNIC: "*Warning* $Broadcom.Description $Broadcom.driverversion;$thebody = $thebody + "<br>NIC: *Warning*" + $Broadcom.Description + " <b>" + $Broadcom.driverversion + "</b>"}	
		
			write-host `nNIC Driver... -background "white" -foreground "Darkblue"
			$NicDriverVer = Reg query "\\$computerName\HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0000\DriverVersion"
			write-host $NicDriverVer
		#>

    ############# Build HTML ###########################
    $thecollection = $collDC | Select-Object Item,Value,Description,s 
    $DNShostname = [System.Net.Dns]::GetHostByName(($env:computerName))
    $hostname = $DNShostname.Hostname
    $a =  "<style>BODY{background-color:White;}" 
    $a = $a + "TABLE{width: 96%;border-width: 1px;border-style: solid;border-color: White;border-collapse: collapse;white-space:nowrap;}"
    $a = $a + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: White;background-color:LightGrey;white-space:nowrap}"
    $a = $a + "TD{border-width: 0px;padding: 0px;border-style: solid;border-color: White;text-indent: 5px;background-color:White;white-space:nowrap}</style>"
    $a = $a + "<table style='width: 100%'><th style='border=2 ;border-top-color: lightgrey;text-align:left;background-color:Green;font-size:small;color:White;margin-left:10px'>"+$org+"</th></table>"  
    $a = $a + "<table><tr><td> </td><td style='text-align:middle;font-size:small'> <b>" + $Header + "</b> - " + " $computerName" + " </td><td style='text-align:right'>$Service</td></tr></table>"
    $thebody = $thecollection | ConvertTo-HTML -head $a  | ForEach-Object {$PSItem -replace "<td>Offline</td>", "<td style='background-color:#FF8080'>Offline</td>"} | Out-String
    ##### Format Cell Status Width - Color #############
            $thebody = $thebody | ForEach-Object {$PSItem -replace "<td>green</td>", "<td style='background-color:green'></td>"} | Out-String
            $thebody = $thebody | ForEach-Object {$PSItem -replace "<td>yellow</td>", "<td style='background-color:yellow'></td>"} | Out-String
            $thebody = $thebody | ForEach-Object {$PSItem -replace "<td>red</td>", "<td style='background-color:red'></td>"} | Out-String
            $thebody = $thebody | ForEach-Object {$PSItem -replace "<th>S</th>", "<th style='width:1%;color:lightgrey'>S</th>"} | Out-String
    ######### Footer
            $end = Get-Date;$ts = New-TimeSpan $start $end
            $thebody = $thebody + "<font size=2 color=lightgrey><br>Node: $hostname | RunTime:  "+ (get-date).ToString() + " | Duration: "+$ts.hours+":"+ $ts.Minutes+":"+$ts.Seconds 
            $thebody = $thebody + " | Version: $ver |</font><br><br>"
	If ($email.IsPresent){
	$subject = 'DC Health : ' + $ComputerName
	send-mailmessage -smtpServer 'smtp.za.dov' -From $from -to $to -Subject $subject -body $thebody -BodyAsHtml
	write-host `n message sent to $to
	}

###################################################################################
# // Write JSON API
###################################################################################
write-host Writing JSON $ReportPath$ComputerName".JSON"
$collDC | ConvertTo-Json | Set-Content $ReportPath$ComputerName".JSON"

