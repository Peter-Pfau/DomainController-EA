# Code Snippets

### HostName
```PowerShell
$DNShostname = [System.Net.Dns]::GetHostByName(($env:computerName))
$hostname = $DNShostname.Hostname
```
