# DomainController-EA
Domain Controller Management and Monitoring

<a href="./Get-DCHealth">Get-DCHealth Documentation</a>

# Todo
## Add dynamic event lookups
$events4011 = Get-WinEvent -computername $DCname -FilterHashtable @{ logname = "DNS Server"; ID = "4011"; StartTime = [datetime]::today}
$events = Get-WinEvent -computername $DCname -FilterHashtable @{ logname = "DNS Server"; ID = "4015"; StartTime = [datetime]::today}
$events = Get-WinEvent -computername $DCname -FilterHashtable @{ logname = "DNS Server"; ID = "4016"; StartTime = [datetime]::today}
