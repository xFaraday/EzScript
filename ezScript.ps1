function ezBanner(){
    Write-Host '
    ________             ______                       __             __     
    |        \           /      \                     |  \           |  \    
    | $$$$$$$$ ________ |  $$$$$$\  _______   ______   \$$  ______  _| $$_   
    | $$__    |        \| $$___\$$ /       \ /      \ |  \ /      \|   $$ \  
    | $$  \    \$$$$$$$$ \$$    \ |  $$$$$$$|  $$$$$$\| $$|  $$$$$$\\$$$$$$  
    | $$$$$     /    $$  _\$$$$$$\| $$      | $$   \$$| $$| $$  | $$ | $$ __ 
    | $$_____  /  $$$$_ |  \__| $$| $$_____ | $$      | $$| $$__/ $$ | $$|  \
    | $$     \|  $$    \ \$$    $$ \$$     \| $$      | $$| $$    $$  \$$  $$
     \$$$$$$$$ \$$$$$$$$  \$$$$$$   \$$$$$$$ \$$       \$$| $$$$$$$    \$$$$ 
                                                          | $$               
                                                          | $$               
                                                           \$$         
                                                                    BY: Keyboard Cowboys
'                                                           
}

function createDir() {
    New-Item -ItemType Directory -Path "C:\Program Files\ezScript" -Force
}

function policyAudit() {
    Write-Host "Creating audit policies..." -ForegroundColor Gray
    try {
        auditpol /set /category:"Account Logon" /success:enable 
        auditpol /set /category:"Account Logon" /failure:enable
        auditpol /set /category:"Account Management" /success:enable
        auditpol /set /category:"Account Management" /failure:enable
        auditpol /set /category:"DS Access" /success:enable
        auditpol /set /category:"DS Access" /failure:enable
        auditpol /set /category:"Logon/Logoff" /success:enable
        auditpol /set /category:"Logon/Logoff" /failure:enable
        auditpol /set /category:"Object Access" /success:enable
        auditpol /set /category:"Object Access" /failure:enable
        auditpol /set /category:"Policy Change" /success:enable
        auditpol /set /category:"Policy Change" /failure:enable
        auditpol /set /category:"Privilege Use" /success:enable
        auditpol /set /category:"Privilege Use" /failure:enable
        auditpol /set /category:"Detailed Tracking" /success:enable
        auditpol /set /category:"Detailed Tracking" /failure:enable
        auditpol /set /category:"System" /success:enable 
        auditpol /set /category:"System" /failure:enable
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\policyAudit.txt"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow
    }
}

function globalAudit() {
    Write-Host "Adding global audit policies..." -ForegroundColor Gray
    $OSWMI = Get-WmiObject Win32_OperatingSystem -Property Caption,Version
    $OSName = $OSWMI.Caption
    if ([regex]::Match($OSName.contains,"server")){
        try {
            auditpol /resourceSACL /set /type:File /user:"Domain Admins" /success /failure /access:FW
            auditpol /resourceSACL /set /type:Key /user:"Domain Admins" /success /failure /access:FW
        }
        catch {
            Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\globalAudit.txt"
            Write-Host "Writing error to file" -ForegroundColor DarkYellow

        }
    }
    else {
        try {
            auditpol /resourceSACL /set /type:File /user:Administrator /success /failure /access:FW
            auditpol /resourceSACL /set /type:Key /user:Administrator /success /failure /access:FW    
            
        }
        catch {
            Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\globalAudit.txt"
            Write-Host "Writing" -ForegroundColor DarkYellow
        }

    }
}

function smbShare() {
    If ($PSVersionTable.PSVersion -ge [version]"3.0") { $OSWMI = Get-CimInstance Win32_OperatingSystem -Property Caption,Version }
    Else { $OSWMI = Get-WmiObject Win32_OperatingSystem -Property Caption,Version }
    $OSVer = [version]$OSWMI.Version
    $OSName = $OSWMI.Caption
    # SMBv1 server
    # Windows v6.2 and later (client & server OS)
    If ($OSVer -ge [version]"6.2") { If ((Get-SmbServerConfiguration).EnableSMB1Protocol) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } }
    # Windows v6.0 & 6.1 (client & server OS)
    ElseIf ($OSVer -ge [version]"6.0" -and $OSVer -lt [version]"6.2") { Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name SMB1 -Value 0 -Type DWord }
    # SMBv1 client
    # Windows v6.3 and later (server OS only)
    If ($OSVer -ge [version]"6.3" -and $OSName -match "\bserver\b") { If ((Get-WindowsFeature FS-SMB1).Installed) { Remove-WindowsFeature FS-SMB1 } }
    # Windows v6.3 and later (client OS)
    ElseIf ($OSVer -ge [version]"6.3" -and $OSName -notmatch "\bserver\b") {
        If ((Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State -eq "Enabled") { Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol }
    }
    # Windows v6.2, v6.1 and v6.0 (client and server OS)
    ElseIf ($OSVer -ge [version]"6.0" -and $OSVer -lt [version]"6.3") {
        $svcLMWDependsOn = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\).DependOnService
        If ($svcLMWDependsOn -contains "MRxSmb10") {
            $svcLMWDependsOn = $svcLMWDependsOn | Where-Object{$_ -ne "MRxSmb10"}
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\ -Name DependOnService -Value $svcLMWDependsOn -Type MultiString
        }
        Set-Service mrxsmb10 -StartupType Disabled
    }
}
function smbGood() {
    try {
        If ($PSVersionTable.PSVersion -ge [version]"3.0") { $OSWMI = Get-CimInstance Win32_OperatingSystem -Property Caption,Version }
        Else { $OSWMI = Get-WmiObject Win32_OperatingSystem -Property Caption,Version }
        $OSVer = [version]$OSWMI.Version
        $OSName = $OSWMI.Caption
        # Windows v6.2 and later (client & server OS)
        If ($OSVer -ge [version]"6.2") { If ((Get-SmbServerConfiguration).EnableSMB1Protocol) { Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force } }
        # Windows v6.0 & 6.1 (client & server OS)
        ElseIf ($OSVer -ge [version]"6.0" -and $OSVer -lt [version]"6.2") { Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters SMB2 -Type DWORD -Value 1 -Force}
        # Windows v6.3 and later (server OS only)
        If ($OSVer -ge [version]"6.3" -and $OSName -match "\bserver\b") { If ((Get-WindowsFeature FS-SMB2).Installed) { Install-WindowsFeature FS-SMB2 } }
        # Windows v6.3 and later (client OS)
        ElseIf ($OSVer -ge [version]"6.3" -and $OSName -notmatch "\bserver\b") {
            If ((Get-WindowsOptionalFeature -Online -FeatureName smb2protocol).State -eq "Disabled") { Enable-WindowsOptionalFeature -Online -FeatureName smb2protocol }
        }
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\smbGood.txt"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow 
    }

}
function groupPolicy() {
    Write-Host "Creating Group Policies..." -ForegroundColor Gray
    try {
        Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName PreventAutoRun -Type DWord -Data 1
        Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SearchCompanion" -ValueName DisableContentFileUpdates -Type DWord -Data 1
        Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\IIS" -ValueName PreventIISInstall -Type DWord -Data 1
        Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName NoAutoUpdate -Type DWord -Data 0

    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\groupPolicy.txt"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow
    }

}

function telnetEnable() {
    Write-Host "Disabling telnet..." -ForegroundColor Gray
    try {
        dism /online /Disable-feature /featurename:TelnetClient /NoRestart
        dism /online /Disable-feature /featurename:TelnetServer /NoRestart 
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\telnetEnable.txt"
        Write-Host "writing error to file" -ForegroundColor DarkYellow
    }
}
function hostFirewall() {
    Write-Host "Configuring firewall rules..." -ForegroundColor Gray
    try {
        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\hostFirewall.txt"
        Write-host "Writing error to file" -ForegroundColor DarkYellow
    }
}

function winRM() {
    Write-Host "Disabling WinRm..." -ForegroundColor Gray
    try {
        Disable-PSRemoting -Force
        Set-Item wsman:\localhost\client\trustedhosts * -Force
        Set-PSSessionConfiguration -Name "Microsoft.PowerShell" -SecurityDescriptorSddl "O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;WD)(A;;GA;;;IU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\winRM.txt"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow
    }
}

function anonLdap() {
    Write-Host "Disabling anonymous LDAP..." -ForegroundColor Gray
    $OSWMI = (Get-WmiObject Win32_OperatingSystem).Caption
    $RootDSE = Get-ADRootDSE
    $ObjectPath = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $RootDSE.ConfigurationNamingContext
    switch -wildcard($OSWMI){
        '*Windows 10*' {
            Write-Warning "Localhost is not a windows server. Moving on to next function"
        }
        '*Windows 8.1*' {
            Write-Warning "Localhost is not a windows server. Moving on to next function"
        }
        '*Windows 8*' {
            Write-Warning "Localhost is not a windows server. Moving on to next function"
        }
        'Windows 7*'{
            Write-Warning "Localhost is not a windows server. Moving on to next function"
        }
        '*Windows Vista*'{
            Write-Warning "Localhost is not a windows server. Moving on to next function"
        }
        '*Windows XP*'{
            Write-Warning "Localhost is not a windows server. Moving on to next function"
        }
        '*Windows Server*'{
            try {
                Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1' }
            }
            catch {
                Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\anonLdap.txt"
                Write-Host "Writing error to file" -ForegroundColor DarkYellow        
            }
        }
        default {
            Write-Output "Unknown OS: $OS"
        }
    }
}
function defenderConfig() {
    Write-Host "Configuring WinDefender" -ForegroundColor Gray
    try {
        setx /M MP_FORCE_USE_SANDBOX 1
        Set-MpPreference -EnableRealtimeMonitoring $true
        Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
        Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\defenderConfig.txt"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow
    }
}

function registryKeys() {
    Write-Host "Configuring registry keys..." -ForegroundColor Gray
    try {
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
        reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
        reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
        reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f   
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
        reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
        reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f
        reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f
        reg ADD HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f            
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\registryKeys.txt"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow
    }
}

function techAccount() {
    Write-Host "configuring techaccount..." -ForegroundColor Gray
    $OS = (Get-WmiObject Win32_OperatingSystem).Caption
    switch -wildcard($OS){
        '*Windows 10*'{
            try {
                $Username = "techie"
                $Password = "c2VjdXJld2luZG93c3Bhc3N3b3JkMTIz"
                $passwordplaintext = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Password))
                cmd.exe /c "net user $Username $passwordplaintext /add /y"
                cmd.exe /c "net localgroup Administrators $Username /add"            
            }
            catch {
                Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\techAccount.txt"
                Write-Host "Writing error to file" -ForegroundColor DarkYellow
            }    
        }
        '*Windows 8.1*' {
            try {
                $Username = "techie"
                $Password = "c2VjdXJld2luZG93c3Bhc3N3b3JkMTIz"
                $passwordplaintext = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Password))
                cmd.exe /c "net user $Username $passwordplaintext /add /y"
                cmd.exe /c "net localgroup Administrators $Username /add"            
            }
            catch {
                Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\techAccount.txt"
                Write-Host "Writing error to file" -ForegroundColor DarkYellow
            }
        }
        '*Windows 8*' {
            try {
                $Username = "techie"
                $Password = "c2VjdXJld2luZG93c3Bhc3N3b3JkMTIz"
                $passwordplaintext = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Password))
                cmd.exe /c "net user $Username $passwordplaintext /add /y"
                cmd.exe /c "net localgroup Administrators $Username /add"            
            }
            catch {
                Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\techAccount.txt"
                Write-Host "Writing error to file" -ForegroundColor DarkYellow
            }
        }
        '*Windows 7*' {
            try {
                $Username = "techie"
                $Password = "c2VjdXJld2luZG93c3Bhc3N3b3JkMTIz"
                $passwordplaintext = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Password))
                cmd.exe /c "net user $Username $passwordplaintext /add /y"
                cmd.exe /c "net localgroup Administrators $Username /add"            
            }
            catch {
                Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\techAccount.txt"
                Write-Host "Writing error to file" -ForegroundColor DarkYellow
            }
        }
        '*Windows Vista*'{
            try {
                $Username = "techie"
                $Password = "c2VjdXJld2luZG93c3Bhc3N3b3JkMTIz"
                $passwordplaintext = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Password))
                cmd.exe /c "net user $Username $passwordplaintext /add /y"
                cmd.exe /c "net localgroup Administrators $Username /add"            

            }
            catch {
                Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\techAccount.txt"
                Write-Host "Writing error to file" -ForegroundColor DarkYellow
            }
        }
        '*Windows XP*'{
            try {
                $Username = "techie"
                $Password = "c2VjdXJld2luZG93c3Bhc3N3b3JkMTIz"
                $passwordplaintext = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Password))
                cmd.exe /c "net user $Username $passwordplaintext /add /y"
                cmd.exe /c "net localgroup Administrators $Username /add"            

            }
            catch {
                Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\techAccount.txt"
                Write-Host "Writing error to file" -ForegroundColor DarkYellow
            }
        }
        '*Windows Server*' {
            Write-Output "This is a server enabled device. Skipping function."
        }
        default {
            Write-Output "Unknown OS: $OS"
        }
    }
}

function homeGroup() {
    Write-Host "Configuring HomeGroup Services..." -ForegroundColor Gray
    try {
        Stop-Service "HomeGroupListener"
        Set-Service "HomeGroupListener" - StartupType Disabled
        Stop-Service "HomeGroupProvider"
        Set-Service "HomeGroupProvider" -StartupType Disabled

    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\homeGroup.txt"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow
    }
}
function micellaneousStuff() {
    Write-Host "Configuring miscellaneous items..." -ForegroundColor Gray
    try {
        Disable-PSRemoting -Force
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\micellaneousStuff.txt"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow
    }
}
function localPass(){
    Write-Host "Changing local passwords..." -ForegroundColor Gray
    try {
        $userList = @()
        $users = Get-LocalUser
        foreach ($user in $users) {
            $newPassword = -join ((33..126) | Get-Random -Count 16 | Foreach-Object {[char]$_})
            $user | Set-LocalUser -Password (ConvertTo-SecureString -AsPlainText $newPassword -Force)
        
    
        $userFull = [PSCustomObject]@{
            "AccountName" = $user
            "Password" = $newPassword
        }
        
        $userList += $userFull
        $userList | Export-Csv -Path "C:\Program Files\ezScript\localmod.csv" -NoTypeInformation
        }
    
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\localPass"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow
    }
}

function adminChange(){
    Write-Host "Changing Administrators name..." -ForegroundColor Gray
    try {
        $adminName = "Administrator"
        $newAdminname = "Wasabi"
        $adminAccount = Get-LocalUser -Name $adminName

        Rename-LocalUser -Name $adminName -NewName $newAdminname
        $adminGroup = Get-LocalGroup -Name "Administrators"
        $adminGroup.Members.Remove($adminAccount)
        $adminGroup.Members.Add($newAdminname)
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\adminChange.txt"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow

    }
}

function Invoke-ezScript () {
ezBanner
createDir > $null
policyAudit > $null
globalAudit > $null
techAccount > $null
registryKeys > $null
winRM > $null
anonLdap > $null
defenderConfig > $null
hostFirewall > $null
smbShare > $null
smbGood > $null
groupPolicy > $null
telnetEnable > $null
homeGroup > $null
micellaneousStuff > $null
adminChange > $null
localPass > $null
}
Invoke-ezScript
