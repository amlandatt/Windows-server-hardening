#Interactive Logon
#Interactive logon: Ref No. 2.3.7.1 - Do not display last user name' to 'Enabled'
#Interactive logon: Ref No. 2.3.7.2 - Do not require CTRL+ALT+DEL to Disabled
#Interactive logon: Ref No. 2.3.7.3 - Machine inactivity limit' to 900 or fewer second(s), but not 0
#Interactive logon: Ref No. 2.3.7.4 - Message text for users attempting to log on
#Interactive logon: Ref No. 2.3.7.5 - Message title for users attempting to log on
#Interactive logon: Ref No. 2.3.7.6 - Number of previous logons to cache (in case domain controller is not available)' to '4 or fewer logon(s)'
#Interactive logon: Ref No. 2.3.7.7 - Prompt user to change password before expiration' to 'between 5 and 14 days'
#Interactive logon: Ref No. 2.3.7.8 - Require Domain Controller authentication to unlock workstation to Enabled
#Interactive logon: Ref No.Machine account lockout threshold
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "DontDisplayLastUserName" -Value 1 -Type DWORD -Verbose
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "DisableCAD" -Value 0 -Type DWORD -Verbose
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "InactivityTimeoutSecs" -Value 300 -Type DWORD -Verbose
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "LegalNoticeText" -Value "WARNING : Unauthorized access to this system is forbidden and will be prosecuted by law. By accessing this system, you agree that your actions may be monitored if unauthorized usage is suspected" -Type String -Verbose
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "LegalNoticeCaption" -Value "HMH" -Type String -Verbose
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name "cachedlogonscount" -Value 4 -Type DWORD -Verbose
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name "passwordexpirywarning" -Value 10 -Type DWORD -Verbose
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name "ForceUnlockLogon" -Value 1 -Type DWORD -Verbose
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "MaxDevicePasswordFailedAttempts" -Value 5 -Type DWORD -Verbose

#Autoplay 
#Autoplay: Ref No. 18.9.8.3 - Turn off Autoplay to 'Enabled:All drives'
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name "NoDriveTypeAutoRun" -Value 1 -Type DWORD -Verbose   


#EventLog
#Security: Ref No. 18.9.26.2.2 - Maximum Log Size (KB) 
#System: Ref No. 18.9.26.4.2 - Maximum Log Size (KB)
#Application: Ref No. 18.9.26.1.2 - Maximum Log Size (KB) 
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security\" -Name "MaxSize" -Value 196608 -Type DWORD -Verbose   
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System\" -Name "MaxSize" -Value 102400 -Type DWORD -Verbose    
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\" -Name "MaxSize" -Value 32768 -Type DWORD -Verbose    
#Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security\" -Name "MaxSize" -Value 196608 -Type DWORD -Verbose   
#Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System\" -Name "MaxSize" -Value 102400 -Type DWORD -Verbose    
#Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\" -Name "MaxSize" -Value 32768 -Type DWORD -Verbose    

# Configuration Definition
Configuration CIS_WindowsServer2016_v110 {
   param (
       [string[]]$NodeName ='localhost'
       )
   Node $NodeName {
#  18.5.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'
       Registry 'AllowInsecureGuestAuth' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
          ValueName    = 'AllowInsecureGuestAuth'
          ValueType    = 'DWord'
          ValueData    = '0'
       }
	   
 #  9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'Off (recommended)'
       Registry 'EnableFirewallDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
           ValueName   = 'EnableFirewall'
           ValueType   = 'DWord'
           ValueData   = '0'
       }
	   
	  #  18.8.49.1.1 (L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'
       Registry 'EnableNTPClient' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
          ValueName  = 'Enabled'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.49.1.2 (L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only)
       Registry 'EnableNTPServer' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer'
          ValueName  = 'Enabled'
          ValueType  = 'DWord'
          ValueData  = '1'
       }	   

#  9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'Off (recommended)'
       Registry 'EnableFirewallPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'EnableFirewall'
          ValueType    = 'DWord'
          ValueData    = '0'
       }
	   
#  9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'Off (recommended)'
       Registry 'EnableFirewallPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'EnableFirewall'
          ValueType    = 'DWord'
          ValueData    = '0'
       }	  
	}
}
