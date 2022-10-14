#Elevate Admin rights
Add-Type -AssemblyName System.Windows.Forms

$ErrorActionPreference = 'SilentlyContinue'
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}
#Restore Point
$Answer = $null
do {
    $Answer = Read-Host -Prompt 'Soll ein Restore Point erstellt werden?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($answer -match "[yY]") {
    Write-Host "Creating Restore Point incase something bad happens"

    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"
}

#Winget installieren 
$Answer = $null
do {
    Write-Output "Winget ist ein Tool um Programme zu installieren und zu deinstallieren."
    Write-Output "Es ist zu vergleichen mit Package Manager aus Linux wie: apt, pacman, dnf"
    Write-Output "Winget ist bei manchem Windowsversionen vorinstalliert."
    $Answer = Read-Host -Prompt 'Soll gecheckt werden ob WinGet install werden muss ?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($answer -match "[yY]") {
    Write-Host "Checking winget..."
    # Check if winget is installed
    if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe){
        'Winget Already Installed'
    }  
    else{
        # Installing winget from the Microsoft Store
        Write-Host "Winget not found, installing it now."
        Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
        $nid = (Get-Process AppInstaller).Id
        Wait-Process -Id $nid
        Write-Host Winget Installed
    }
}

#winget dynamischer update
#todo

#Winget dynamischer uninstall 
#todo

#Cortana deaktivieren
$Answer = $null
do {
    $Answer = Read-Host -Prompt 'Sollen Cortana deaktiviert werden?(y/n)'
}
until ($Answer -match "[yYnN]")

if ($answer -match "[yY]") {
    Write-Host "Disabling Cortana..."

    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    Write-Host "Disabled Cortana"
    
}

#OneDrive deaktivieren
$Answer = $null
do {
    $Answer = Read-Host -Prompt 'Sollen OneDrive deaktiviert und deinstalliert werden?(y/n)'
}
until ($Answer -match "[yYnN]")

if ($Answer -match "[yY]") {
    Write-Host "Disabling OneDrive..."

    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
    Write-Host "Uninstalling OneDrive..."
    Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    Start-Sleep -s 2
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Start-Sleep -s 2
    Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
    Start-Sleep -s 2
    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
    
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    Write-Host "Disabled OneDrive"
    
}

#Edge deinstallieren
#todo

$Answer = $null
do {
    $Answer = Read-Host -Prompt 'Soll Windows Darkmode eingestellt werden?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($Answer -match "[yY]") {
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
}

#VC++ installieren
$Answer = $null
do {
    Write-Output "Ich empfehle auf Gaming Rechner VC++ zu installieren."
    $Answer = Read-Host -Prompt 'Sollen VC++ installiert werden?(y/n)'
}
until ($Answer -match "[yYnN]")

if ($Answer -match "[yY]") {
    Write-Output "Prüfe welche Versionen für dich in Frage kommen"
    if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64" -or $env:PROCESSOR_ARCHITECTURE -eq "x64") {
        $vc = @(
            "Microsoft.VC++2015-2022Redist-x86"
            "Microsoft.VC++2013Redist-x86"
            "Microsoft.VC++2012Redist-x86"
            "Microsoft.VC++2010Redist-x86"
            "Microsoft.VC++2008Redist-x86"
            "Microsoft.VC++2005Redist-x86"
            "Microsoft.VC++2015-2022Redist-x64"
            "Microsoft.VC++2013Redist-x64"
            "Microsoft.VC++2012Redist-x64"
            "Microsoft.VC++2010Redist-x64"
            "Microsoft.VC++2008Redist-x64"
            "Microsoft.VC++2005Redist-x64"
        )
    } elseif ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
        $vc = @(
            "Microsoft.VC++2015-2022Redist-x86"
            "Microsoft.VC++2013Redist-x86"
            "Microsoft.VC++2012Redist-x86"
            "Microsoft.VC++2010Redist-x86"
            "Microsoft.VC++2008Redist-x86"
            "Microsoft.VC++2005Redist-x86"
        )
    } elseif ($env:PROCESSOR_ARCHITECTURE -eq "arm64") { #-or $env:PROCESSOR_ARCHITECTURE -eq "arm") {
        $vc = @(
            "Microsoft.VC++2022Redist-arm64"
            "Microsoft.VC++2019Redist-arm64"
        )
    }

    foreach ($program in $vc) {
        winget install -e $program
    }    
}

#Empfolende Settings setzen
$Answer = $null
do {
    Write-Output "Ich empfehle Einige Settings"
    $Answer = Read-Host -Prompt 'Sollen empfolene Settings gesetzt werden?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($Answer -match "[yY]") {
    Write-Host "Hide tray icons..."
    #EnableAutoTray
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
    
    Write-Host "Show Frequent Settings"
    # Show Freqently in Quick access
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type Dword -Value 0
    
    
    Write-Host "Show Recent Settings" 
    # Show recently in Quick access
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type Dword -Value 0
    
    Write-Host "Launch To Settings"
    # Explorer startet in My PC
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    
    Write-Host "Disable News and Interests"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
    
    # Remove "News and Interest" from taskbar
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
    
    # remove "Meet Now" button from taskbar
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled
    
    Write-Host "Showing known file extensions..."
    # Show File Extension
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    
    # Search as icon
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type Dword -Value 1
    
    # remove Microsoft Store from Taskbar (unsicher ob es das macht was ich denke)
    #If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView")) {
    #    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView" -Name "Microsoft.WindowsStore_8wekyb3d8bbwe!App" -Type DWord -Value 1
    
    # remove Microsoft Store from Taskbar (unsicher ob es das macht was ich denke)
    #If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView")) {
    #    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView" -Name "Microsoft.WindowsStore_8wekyb3d8bbwe!App" -Type DWord -Value 1
}



#Device Manager prüfen
$Answer = $null
do {
    Write-Output "Ich empfehle den Device Manager zu prüfen."
    Write-Output "Ob alle Treiber installiert sind."
    $Answer = Read-Host -Prompt 'Sollen Device Manager geöffnet werden?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($Answer -match "[yY]") {
    #Get-PnpDevice
    devmgmt.msc
}

#Aufgaben planung/Task Scheduler prüfen und setzen
#todo

#Event Viewer prüfen
#todo

#Startup checken
#todo

#Disable Features
$Answer = $null
do {
    Write-Output "Ich empfehle Features zu disablen aus Security Gründen."
    $Answer = Read-Host -Prompt 'Sollen empfohlene Features deaktiviert werden?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($Answer -match "[yY]") {
    DISM /online /disable-feature /featurename:Internet-Explorer-Optional-amd64
}

#Auf C:\ werden lnk Dateien gesucht und entfernt
$Answer = $null
do {
    $Answer = Read-Host -Prompt 'Sollen defekte lnk Dateien entfernt werden?(y/n)'
}
until ($Answer -match "[yYnN]")

if ($Answer -match "[yY]") {
    $Answer = $null
    do {
        $Answer = Read-Host -Prompt 'Soll simuliert (sym) werden oder direkt enfernt (del) werden? (sym/del)'
    }
    until ($Answer -eq 'sym' -or $Answer -eq 'del')

    $every_linked_files = Get-ChildItem -Path c:\ -r *.lnk -ErrorAction SilentlyContinue 
    foreach ($every_linked_file in $every_linked_files) {
        [string]$every_path = $every_linked_file.FullName
    
        $sh = New-Object -COM WScript.Shell
        $targetPath = $sh.CreateShortcut($every_path).TargetPath
    
        if ($null -eq $targetPath ) {
            #Write-Output "target path war null "
            $targetPath = "."
        }
        if ($targetPath -eq "") {
            #Write-Output "target path war leer"
            $targetPath = "."
        }
    
        if (Test-Path $targetPath ) {
        }
        else {
            Write-Output "Folgendes existiert nicht: $($targetPath)"
            if ($Answer -eq "sym" ) {
                Write-Output "Daher kann folgendes removed werden: $($every_path)"
            }
            if ($Answer -eq "del" ) {
                Write-Output "Daher wird folgendes removed: $($every_path)"
                Remove-Item $every_path
                if (Test-Path $every_path ) {
                    Write-Output "Remove hat nicht geklappt"
                }
                else {
                    Write-Output "Remove hat geklappt"
                }
            }
        Write-Output ""
        }
    }   
}

#Full Virus Check
$Answer = $null
do {
    $Answer = Read-Host -Prompt 'Soll ein voller Virus Scan durchgeführt werden?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($Answer -match "[yY]") {
    Update-MpSignature
    Set-MpPreference -SignatureScheduleDay Everyday
    Start-MpScan -ScanType FullScan
    #Offline Scan
    #Start-MpWDOScan 
}

#Full Update
$Answer = $null
do {
    Write-Output "Diese Option kann sehr lange dauern."
    $Answer = Read-Host -Prompt 'Soll ein volles Windows Update durchgeführt werden?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($Answer -match "[yY]") {
    #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType::Tls12
    #Trust PowerShell Gallery this will avoid you getting any prompts that it's untrusted
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    #Install NuGet
    Install-PackageProvider -name NuGet -Force
    #Install Module
    Install-Module PSWindowsUpdate
    #Check what updates are required for this server
    Get-WindowsUpdate
    #Accept and install all the updates that it's found are required
    Install-WindowsUpdate -AcceptAll
}

#Disk Cleanup
$Answer = $null
do {
    $Answer = Read-Host -Prompt 'Sollen ein DiskCleanup duchgeführt werden?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($Answer -match "[yY]") {
    #$cleanmgr = "$env:SYSTEMROOT\system32\cleanmgr.exe"
    cleanmgr /verylowdisk
    #Start-Process "$env:SYSTEMROOT\system32\cleanmgr.exe"
    #Start-Process "$env:SYSTEMROOT\system32\cleanmgr.exe" "/lowdisk"
    #Start-Process "$env:SYSTEMROOT\system32\cleanmgr.exe" "/setup"
    #Start-Process "$env:SYSTEMROOT\system32\cleanmgr.exe" "/Autoclean"
}

#Diskdefrag
$Answer = $null
do {
    $Answer = Read-Host -Prompt 'Sollen ein DiskDefrag duchgeführt werden?(y/n)'
}
until ($Answer -match "[yYnN]")
if ($Answer -match "[yY]") {
    dfrgui
    #Start-Process "$env:SYSTEMROOT\system32\dfrgui.exe"
}
