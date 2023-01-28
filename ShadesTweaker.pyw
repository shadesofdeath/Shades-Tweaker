import os
import tkinter as tk
from tkinter import ttk
from titlebar import sun_valley_titlebar
import subprocess
import webbrowser
import psutil
from tkinter.ttk import *
import ping3
from ping3 import ping

selected_checkboxes = []

app_list_tab1 = {
    "Phone":'sc config wuauserv start= disabled',
    "Windows Insıder":'sc config wisvc start= disabled',
    "Bluetooth Support":'sc config bthserv start= disabled',
    "Remote Desktop":'sc config TermService start= disabled',
    "Remote Desktop Configuration":'sc config SessionEnv start= disabled',
    "Windows Mobile Hotspot":'sc config servvisadi start= disabled',
    "Microsoft Edge Update":'sc config edgeupdate start= disabled && sc config edgeupdatem start= disabled',
    "Windows Error Reporting":'sc config WerSvc start= disabled',
    "Remote Registry":'sc config RemoteRegistry start= disabled',
    "Retail Demo":'sc config RetailDemo start= disabled',
    "Wallet Service":'sc config WalletService start= disabled',
    "User experiences & telemetry":'sc config DiagTrack start= disabled',
    "Downloaded Maps Manager":'sc config MapsBroker start= disabled',
    "IP Helper":'sc config iphlpsvc start= disabled',
    "Print Spooler":'sc config Spooler start= disabled',
    "Windows Biometric":'sc config WbioSrvc start= disabled',
    "Windows Image Acquisition":'sc config stisvc start= disabled',
    "SysMain":'sc config SysMain start= disabled',
    "Windows Search":'sc config WSearch start= disabled',
    "Xbox Services":'sc config XboxGipSvc start= disabled && sc config XboxNetApiSvc start= disabled && sc config XblAuthManager start= disabled && sc config XblGameSave start= disabled',
    "Windows Update":'sc config wuauserv start= disabled',
    "Windows Diagnostic Policy":'sc config DPS start= disabled',
    "Windows Defender Firewall":'sc config mpssvc start= disabled',
    "Background Intelligent Transfer":'sc config BITS start= disabled',
    "Problem Reports Control Panel Support":'sc config wercplsupport start= disabled',
    "Program Compatibility Assistant":'sc config PcaSvc start= disabled',
    "Security Health Service":'sc config SecurityHealthService start= disabled',
    "Volume Shadow Copy":'net stop vss && net stop swprv && reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS" /v Start /t REG_DWORD /d 4 /f && reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SWPRV" /v Start /t REG_DWORD /d 4 /f',
    "Windows Remote Management":'net stop winrm && sc config winrm start= disabled',
    "Offline Files":'net stop "CscService" && sc config "CscService" start= disabled',
    "Windows Time":'net stop W32Time && sc config W32Time start= disabled',
    "Windows Action Center":'reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f',
}

app_list_tab2 = {
    "Disabling JPEG Quality Reduction":'Reg.exe delete "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /f && Reg.exe add "HKCU\Control Panel\Desktop" /f',
    "Remove 'Home' Navigation Panel":r'Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f && Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_36354489\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f',
    "Remove OneDrive from Navigation Panel":'Reg.exe add "HKCU\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f',
    "Restore Classic Start Menu (Win 11)":"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V Start_ShowClassicMode /T REG_DWORD /D 1 /F",
    "Remove Chat Button on Taskbar":'reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v TaskbarMn /t REG_DWORD /d 0 /f',
    "Turn Off Play Windows Startup Sound":'Reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation /v DisableStartupSound /t REG_DWORD /d 1 /f && Reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\EditionOverrides /v UserSetting_DisableStartupSound /t REG_DWORD /d 1 /f',
    "File Explorer Classic Ribbon":'Reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked /v {e2bf9676-5f8f-435c-97eb-11607a5bedf7} /t REG_SZ /d "" /f',
    "Disable Widgets":'Reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Dsh /v AllowNewsAndInterests /t REG_DWORD /d 0 /f',
    "Disable Thumbnail Previews File Explorer":'REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V IconsOnly /T REG_DWORD /D 1 /F',
    "Enable Thumbnail Previews File Explorer":'REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V IconsOnly /T REG_DWORD /D 0 /F',
    "Restore Old Context Menu":'Reg.exe add HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2} /ve /t REG_SZ /d "" /f && Reg.exe add HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32 /ve /t REG_SZ /d "" /f',
    "Disable File History":'Reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory /v Disabled /t REG_DWORD /d 1 /f',
    "Remove Taskbar MeetNow Logo":'reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v HideSCAMeetNow /t REG_DWORD /d 1 /f',
    "Disable Online Tips":'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v AllowOnlineTips /t REG_DWORD /d 0 /f',
    "Disable LiveTiles push notifications":'reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications /v NoTileApplicationNotification /t REG_DWORD /d 1 /f',
    "Disable Windows feedback":'reg add HKCU\SOFTWARE\Microsoft\Siuf\Rules /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f && reg delete HKCU\SOFTWARE\Microsoft\Siuf\Rules /v PeriodInNanoSeconds /f && reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f  && reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f',
    "Turn Off Suggested Content Settings app":'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /d "0" /t REG_DWORD /f && reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /d "0" /t REG_DWORD /f && reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /d "0" /t REG_DWORD /f',
    "Disable Peek":'Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f',
    "Disable Transparency Effects":'Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f',
    "Align Taskbar to Left":'Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f',
    "Remove Widgets Button Taskbar":'Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f',
    "Hide Search Button Taskbar":'Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f',
    "Small Taskbar":'REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarSi /T REG_DWORD /D 0 /F',
    "Medium Taskbar":'REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarSi /T REG_DWORD /D 1 /F',
    "Large Taskbar":'REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V TaskbarSi /T REG_DWORD /D 2 /F',
    "Enable Seconds Taskbar Clock (Win10)":'powershell.exe Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSecondsInSystemClock -Value 1 -Force',
    "Enable Hidden Files & Folders":'Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f',
}

app_list_tab3 = {
    "Turn Off Xbox Game Bar":'Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f && Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f',
    "Disable Windows Game Recording Broadcasting":'Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f',
    "Disable Hardware Accelerated":'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "1" /f',
    "Turn Off Game Mode":'Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f && Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f',
    "Windowed Game Optimizations Off":r'Reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "SwapEffectUpgradeCache" /t REG_DWORD /d "1" /f && Reg.exe add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "SwapEffectUpgradeEnable=0;" /f',
    "Disable Fast Startup":'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V HiberbootEnabled /T REG_dWORD /D 0 /F',
    "Disable Power Throttling":'reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f',
    "Disable SysMain (Superfetch)":'sc stop "SysMain" & sc config "SysMain" start=disabled',
    "Disable PreFetch":'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f',
    "Disable Device Guard":'Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /f && Reg.exe delete "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /f && Reg.exe delete "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "RequirePlatformSecurityFeatures" /f && Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /f',
    "Enable TSX (Only Intel)":'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "DisableTsx" /t REG_DWORD /d "0" /f',
    "Disable Speculative Execution":'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f',
    "Disable Full Screen Optimization":'Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f && Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f && Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f && Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f && Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f && Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f && Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f && Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f && Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f && Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f && Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f && Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f && Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f && Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f',
    "Cpu Optimzation":'Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f && Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f',
    "Gpu Tweaks":r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f',
    "Disable Defender":'Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f',
    "Disable MMCSS":'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "4" /f',
    "Memory Optimization":'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "0" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d "0" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionViewSize" /t REG_DWORD /d "192" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "0" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d "3072" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionPoolSize" /t REG_DWORD /d "192" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d "192" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d "1" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "1048576" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PoolUsageMaximum" /t REG_DWORD /d "96" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "AdditionalCriticalWorkerThreads" /t REG_DWORD /d "32" /f && Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "AdditionalDelayedWorkerThreads" /t REG_DWORD /d "32" /f',
    "Disable Hibernate":'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f',
    "Disable Unwanted Services":'sc config RasMan start=disabled && sc config MapsBroker start=disabled && sc config RemoteAccess start=disabled && sc config lfsvc start=disabled && sc config RemoteRegistry start=disabled && sc config SstpSvc start=disabled && sc config KSecPkg start=disabled && sc config rdbss start=demand && sc config LanmanWorkstation start=disabled && sc config LanmanServer start=disabled && sc config DPS start=disabled && sc config WSearch start=disabled && sc config UsoSvc start=disabled && sc config cdrom start=disabled && sc config cbdhsvc start=disabled && sc config CompositeBus start=disabled && sc config DoSvc start=disabled && sc config IRENUM start=disabled && sc config lltdsvc start=disabled && sc config lltdio start=disabled && sc config rspndr start=disabled && sc config NetBIOS start=disabled',
    "Disable Hyper-V":'bcdedit /set hypervisorlaunchtype off',
}

app_list_tab4 = {
    "7zip":'winget install --id=7zip.7zip  -e',
    "Winrar":'winget install --id=RARLab.WinRAR  -e',
    "Discord":'winget install --id=Discord.Discord  -e',
    "IrfanView":'winget install --id=IrfanSkiljan.IrfanView  -e',
    "VLC Media Player":'winget install --id=VideoLAN.VLC  -e',
    "Google Chrome":'winget install --id=Google.Chrome  -e',
    "Mozilla Firefox":'winget install --id=Mozilla.Firefox  -e',
    "Brave":'winget install --id=Brave.Brave  -e',
    "Opera":'winget install --id=Opera.Opera  -e',
    "Vivaldi":'winget install --id=VivaldiTechnologies.Vivaldi  -e',
    "Git":'winget install --id=Git.Git  -e',
    "Github Desktop":'winget install --id=GitHub.GitHubDesktop.Beta  -e',
    "Notepad++":'winget install --id=Notepad++.Notepad++  -e',
    "Visual Studio Code":'winget install --id=Microsoft.VisualStudioCode  -e',
    "Windows Terminal":'winget install --id=Microsoft.WindowsTerminal  -e',
    "Audacity":'winget install --id=Audacity.Audacity  -e',
    "Kodi":'winget install --id=XBMCFoundation.Kodi  -e',
    "Steam":'winget install --id=Valve.Steam  -e',
    ".NET Framework":'winget install --id=Microsoft.DotNet.Framework.DeveloperPack_4  -e',
    "Adguard":'winget install --id=AdGuard.AdGuard  -e',
    "ScreenRecorder":'winget install --id=kimhwan.ScreenRecorder  -e',
    "Bing Wallpaper":'winget install --id=Microsoft.BingWallpaper  -e',
    "Bit Game Booster":'winget install --id=BitGuardian.BitGameBooster  -e',
    "BitDefender Agent":'winget install --id=Bitdefender.Bitdefender  -e',
    "BlueStacks":'winget install --id=BlueStack.BlueStacks  -e',
    "CapCut":'winget install --id=ByteDance.CapCut  -e',
    "CCleaner":'winget install --id=Piriform.CCleaner  -e',
    "Cent Browser":'winget install --id=CentStudio.CentBrowser  -e',
    "ChatGPT":'winget install --id=lencx.ChatGPT  -e',
    "Chromium":'winget install --id=eloston.ungoogled-chromium  -e',
    "AIMP":'winget install --id=AIMP.AIMP  -e',
    "AIDA64 Extreme":'winget install --id=FinalWire.AIDA64.Extreme  -e',
    "AnyDesk":'winget install --id=AnyDeskSoftwareGmbH.AnyDesk  -e',
    "APK Installer":'winget install --id=wherewhere.APKInstaller.Classic  -e',
    "Cloudflare WARP":'winget install --id=Cloudflare.Warp  -e',
    "FileZilla Client":'winget install --id=TimKosse.FileZilla.Client  -e',
    "Epic Games Launcher":'winget install --id=EpicGames.EpicGamesLauncher  -e',
    "ESET Nod32":'winget install --id=ESET.Nod32  -e',
    "ExplorerPatcher":'winget install --id=valinet.ExplorerPatcher.Prerelease  -e',
    "Driver Booster":'winget install --id=IObit.DriverBooster  -e',
    "ElevenClock":'winget install --id=SomePythonThings.ElevenClock  -e',
    "Defraggler":'winget install --id=Piriform.Defraggler  -e',
    "Deluge BitTorrent":'winget install --id=DelugeTeam.Deluge  -e',
    "DirectX Runtime Web":'winget install --id=Microsoft.DirectX  -e',
    "CubePDF":'winget install --id=CubeSoft.CubePDF  -e',
    "CPUID CPU-Z":'winget install --id=CPUID.CPU-Z  -e',
    "Lightshot":'winget install --id=Skillbrains.Lightshot  -e',
    "foobar2000":'winget install --id=PeterPawlowski.foobar2000  -e',
    "Free Download Manager":'winget install --id=SoftDeluxe.FreeDownloadManager  -e',
    "Telegram Desktop":'winget install --id=Telegram.TelegramDesktop  -e',
    "PotPlayer":'winget install --id=Daum.PotPlayer  -e',
    "Spotify":'winget install --id=Spotify.Spotify  -e',
    "HandBrake":'winget install --id=HandBrake.HandBrake  -e',
    "Visual C++ 2015-2022 AIO":'winget install --id=Microsoft.VCRedist.2015+.x64  -e',
    "Opera GX":'winget install --id=Opera.OperaGX  -e',
    "LibreOffice":'winget install --id=TheDocumentFoundation.LibreOffice  -e',
    "AdGuardVPN":'winget install --id=AdGuard.AdGuardVPN  -e',
    "Microsoft PC Manager":'winget install --id=Microsoft.PCManager  -e',
    ".NET Framework 4.8":'winget install --id=Microsoft.DotNet.Framework.DeveloperPack_4  -e',
    "EarTrumpet":'winget install --id=File-New-Project.EarTrumpet  -e',
    "Popcorn-Time":'winget install --id=PopcornTime.Popcorn-Time  -e',
    "UUP Media Creator":'winget install --id=ITDevTeam.UUPMediaCreator  -e',
    "Ubuntu 22.04 LTS":'winget install --id=Canonical.Ubuntu.2204  -e',
    "Malwarebytes":'winget install --id=Malwarebytes.Malwarebytes  -e',
    "Revo Uninstaller Pro":'winget install --id=RevoUninstaller.RevoUninstallerPro  -e',
    "Google Earth Pro":'winget install --id=Google.EarthPro  -e',
}

app_list_tab5 = {  
    "Cortana":'winget uninstall cortana --accept-source-agreements --silent',
    "Skype":'winget uninstall skype --accept-source-agreements --silent',
    "Camera":'winget uninstall Microsoft.WindowsCamera_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Sketch":'winget uninstall Microsoft.ScreenSketch_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Xbox Gaming App":'winget uninstall Microsoft.GamingApp_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Xbox App":'winget uninstall Microsoft.XboxApp_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Xbox TCUI":'winget uninstall Microsoft.Xbox.TCUI_8wekyb3d8bbwe --accept-source-agreements --silent',
    "XboxSpeechToTextOverlay":'winget uninstall Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe --accept-source-agreements --silent',
    "XboxIdentityProvider":'winget uninstall Microsoft.XboxIdentityProvider_8wekyb3d8bbwe --accept-source-agreements --silent',
    "XboxGamingOverlay":'winget uninstall Microsoft.XboxGamingOverlay_8wekyb3d8bbwe --accept-source-agreements --silent',
    "XboxGameOverlay":'winget uninstall Microsoft.XboxGameOverlay_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Groove Music":'winget uninstall Microsoft.ZuneMusic_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Feedback Hub":'winget uninstall Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Microsoft-Tips":'winget uninstall Microsoft.Getstarted_8wekyb3d8bbwe --accept-source-agreements --silent',
    "3D Viewer":'winget uninstall 9NBLGGH42THS --accept-source-agreements --silent',
    "MS Solitaire":'winget uninstall Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Paint-3D":'winget uninstall 9NBLGGH5FV99 --accept-source-agreements --silent',
    "Weather ":'winget uninstall Microsoft.BingWeather_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Mail / Calendar":'winget uninstall microsoft.windowscommunicationsapps_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Your Phone":'winget uninstall Microsoft.YourPhone_8wekyb3d8bbwe --accept-source-agreements --silent',
    "People":'winget uninstall Microsoft.People_8wekyb3d8bbwe --accept-source-agreements --silent',
    "MS Pay ":'winget uninstall Microsoft.Wallet_8wekyb3d8bbwe --accept-source-agreements --silent',
    "MS Maps":'winget uninstall Microsoft.WindowsMaps_8wekyb3d8bbwe --accept-source-agreements --silent',
    "OneNote":'winget uninstall Microsoft.Office.OneNote_8wekyb3d8bbwe --accept-source-agreements --silent',
    "MS Office":'winget uninstall Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Voice Recorder":'winget uninstall Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Movies & TV":'winget uninstall Microsoft.ZuneVideo_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Mixed Reality-Portal":'winget uninstall Microsoft.MixedReality.Portal_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Sticky Notes":'winget uninstall Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Get Help":'winget uninstall Microsoft.GetHelp_8wekyb3d8bbwe --accept-source-agreements --silent',
    "OneDrive":'winget uninstall Microsoft.OneDrive --accept-source-agreements --silent',
    "Calculator":'winget uninstall Microsoft.WindowsCalculator_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Microsoft TO Do":'winget uninstall Microsoft.Todos_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Power Automate":'winget uninstall Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Bing News":'winget uninstall Microsoft.BingNews_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Microsoft Teams":'winget uninstall MicrosoftTeams_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Microsoft Family":'winget uninstall MicrosoftCorporationII.MicrosoftFamily_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Quick Assist":'winget uninstall MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Disney+":'winget uninstall MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe --accept-source-agreements --silent',
    "ClipChamp":'winget uninstall Clipchamp.Clipchamp_yxz26nhyzhsrt --accept-source-agreements --silent',
    "WhatsApp":'winget uninstall 5319275A.WhatsAppDesktop_cv1g1gvanyjgm --accept-source-agreements --silent',
    "Spotify Music":'winget uninstall SpotifyAB.SpotifyMusic_zpdnekdrzrea0 --accept-source-agreements --silent',
    "Microsoft Store":'winget uninstall Microsoft.WindowsStore_8wekyb3d8bbwe --accept-source-agreements --silent',
    "HEIFImageExtension":'winget uninstall Microsoft.HEIFImageExtension_8wekyb3d8bbwe --accept-source-agreements --silent',
    "HEVCVideoExtension":'winget uninstall Microsoft.HEVCVideoExtension_8wekyb3d8bbwe --accept-source-agreements --silent',
    "RawImageExtension":'winget uninstall Microsoft.RawImageExtension_8wekyb3d8bbwe --accept-source-agreements --silent',
    "StorePurchaseApp":'winget uninstall Microsoft.StorePurchaseApp_8wekyb3d8bbwe --accept-source-agreements --silent',
    "VP9VideoExtensions":'winget uninstall Microsoft.VP9VideoExtensions_8wekyb3d8bbwe --accept-source-agreements --silent',
    "WebMediaExtensions":'winget uninstall Microsoft.WebMediaExtensions_8wekyb3d8bbwe --accept-source-agreements --silent',
    "WebpImageExtension":'winget uninstall Microsoft.WebpImageExtension_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Windows Alarms":'winget uninstall Microsoft.WindowsAlarms_8wekyb3d8bbwe --accept-source-agreements --silent',
    "Windows Camera":'winget uninstall Microsoft.WindowsCamera_8wekyb3d8bbwe --accept-source-agreements --silent',
    "WebExperience":'winget uninstall MicrosoftWindows.Client.WebExperiencecw5n1h2txyewy --accept-source-agreements --silent',
    "PC Health tool":'winget uninstall {6A2A8076-135F-4F55-BB02-DED67C8C6934} --accept-source-agreements --silent',
    "Screen Capture":'winget uninstall {6A2A8076-135F-4F55-BB02-DED67C8C6934} --accept-source-agreements --silent',
    "Paint":'winget install --id 9PCFS5B6T72H --accept-source-agreements --silent --accept-package-agreements',
    "Calculator":'winget install --id 9WZDNCRFHVN5 --accept-source-agreements --silent --accept-package-agreements',
    "Photo":'winget install --id 9WZDNCRFJBH4 --accept-source-agreements --silent --accept-package-agreements',
    "Notepad":'winget install --id 9MSMLRH6LZF3 --accept-source-agreements --silent --accept-package-agreements',
}

app_list_tab6 = {
    
}

app_list_tab7 = {
    
}

WINDOW_TITLE = " Shades Tweaker  |  Windows 10 - 11"
WINDOW_MINSIZE = (1200, 500)
WINDOW_POSITION = (580, 250)
root = tk.Tk()
root.overrideredirect(True)
root.maxsize(1200, 500)
root.minsize(WINDOW_MINSIZE[0], WINDOW_MINSIZE[1])
root.geometry(str(WINDOW_MINSIZE[0]) + "x" + str(WINDOW_MINSIZE[1]) + "+" + str(WINDOW_POSITION[0]) + "+" + str(WINDOW_POSITION[1]))
root.title(WINDOW_TITLE)

root.tk.call("source", "tema/sun-valley.tcl")
root.tk.call("set_theme", "dark")
icon = tk.PhotoImage(file='assets/titlelogo.png')
root.iconbitmap(default='assets/tasklogo.ico')

def change_theme():
    if root.tk.call("ttk::style", "theme", "use") == "sun-valley-dark":
        root.tk.call("set_theme", "light")
    else:
        root.tk.call("set_theme", "dark")

big_frame = ttk.Frame(root)
big_frame.pack()
titlebar = sun_valley_titlebar.Titlebar(root, big_frame, icon, WINDOW_TITLE, True, True, True, WINDOW_MINSIZE[0], WINDOW_MINSIZE[1])
frame_for_tabs = ttk.Frame(root)
frame_for_tabs.pack()
tabs = ttk.Notebook(frame_for_tabs)
tab1 = ttk.Frame(tabs)
tab2 = ttk.Frame(tabs)
tab3 = ttk.Frame(tabs)
tab4 = ttk.Frame(tabs)
tab5 = ttk.Frame(tabs)
tab6 = ttk.Frame(tabs)
tab7 = ttk.Frame(tabs)
tabs.add(tab1, text="⚙️ Windows Services ( Disable )")
tabs.add(tab2, text="🎨 Customization & personalization")
tabs.add(tab3, text="🎮 Gaming Tweaks")
tabs.add(tab4, text="📦 Install Packages ( WinGET)")
tabs.add(tab5, text="🧹 Windows Debloater")
tabs.add(tab6, text="💻 PC Stats")
tabs.add(tab7, text="🖤 About")
info_label1 = ttk.Label(tab7, text="Shades Tweaker is a tool that includes many features for Windows 10 and 11.\nI am not responsible for any problems that may occur on your computer, the control\nis completely in your hands. If you liked this application, please do not hesitate to\n                                                            support me.",wraplength=1200, font=(20))
info_label1.grid(row=2, column=2, columnspan=1, padx=280, pady=50 ,sticky="nse")
donate_button = ttk.Button(tab7, text="Donate 💸", command=lambda: webbrowser.open("https://www.buymeacoffee.com/berkayay"))
donate_button.grid(row=4, column=2, columnspan=1, padx=280, pady=5)
source = ttk.Button(tab7, text="Source Code 🐍", command=lambda: webbrowser.open("https://pbs.twimg.com/media/EX6F_sqWAAQF1Mw.jpg:large"))
source.grid(row=5, column=2, columnspan=1, padx=280, pady=5)
tabs.grid()

def update_stats():
    cpu_percent = psutil.cpu_percent()
    memory_percent = psutil.virtual_memory().percent
    memory_total = psutil.virtual_memory().total / (1024.0 ** 3)
    memory_available = psutil.virtual_memory().available / (1024.0 ** 3)
    memory_used = memory_total - memory_available

    disk_usage = psutil.disk_usage('/')
    disk_total = disk_usage.total / (1024.0 ** 3)
    disk_used = disk_usage.used / (1024.0 ** 3)
    disk_free = disk_usage.free / (1024.0 ** 3)
    disk_usage = psutil.disk_usage('/')
    
    response_time = int(ping3.ping('google.com', unit='ms'))
    ping_label.config(text="Ping: " + str(response_time) + " ms")

    cpu_label.config(text="CPU Usage: " + str(cpu_percent) + "%")
    memory_label.config(text="Memory Usage: " + f"{memory_used:.2f} GB / {memory_total:.2f} GB")
    disk_label.config(text="Disk Usage: " + f"{disk_used:.2f} GB / {disk_total:.2f} GB")
    tab6.after(1000, update_stats)

cpu_label = Label(tab6, text="CPU Usage: ")
cpu_label.place(x=10, y=10)
memory_label = Label(tab6, text="Memory Usage: ")
memory_label.place(x=10, y=40)
disk_label = Label(tab6, text="Disk Usage: ")
disk_label.place(x=10, y=70)
ping_label = Label(tab6, text="Ping: ")
ping_label.place(x=10, y=100)
tab6.after(1000, update_stats)

app_frame_tab1 = ttk.Frame(tab1)
app_frame_tab1.grid()
app_frame_tab2 = ttk.Frame(tab2)
app_frame_tab2.grid()
app_frame_tab3 = ttk.Frame(tab3)
app_frame_tab3.grid()
app_frame_tab4 = ttk.Frame(tab4)
app_frame_tab4.grid()
app_frame_tab5 = ttk.Frame(tab5)
app_frame_tab5.grid()
app_frame_tab6 = ttk.Frame(tab6)
app_frame_tab6.grid()
app_frame_tab7 = ttk.Frame(tab7)
app_frame_tab7.grid()
    
for i , (key,value) in enumerate(app_list_tab1.items()):
    var = tk.IntVar()
    checkbox = ttk.Checkbutton(tab1, text=key, variable=var)
    checkbox.grid(row=i//4, column=i%4, padx=20, pady=5,sticky="w")
    selected_checkboxes.append((checkbox, var, "tab1")) 
    
for i , (key,value) in enumerate(app_list_tab2.items()):
    var = tk.IntVar()
    checkbox = ttk.Checkbutton(tab2, text=key, variable=var)
    checkbox.grid(row=i//4, column=i%4, padx=5, pady=5,sticky="w")
    selected_checkboxes.append((checkbox, var, "tab2")) 

for i , (key,value) in enumerate(app_list_tab3.items()):
    var = tk.IntVar()
    checkbox = ttk.Checkbutton(tab3, text=key, variable=var)
    checkbox.grid(row=i//4, column=i%4, padx=10, pady=10,sticky="w")
    selected_checkboxes.append((checkbox, var, "tab3")) 
    
for i , (key,value) in enumerate(app_list_tab4.items()):
    var = tk.IntVar()
    checkbox = ttk.Checkbutton(tab4, text=key, variable=var)
    checkbox.grid(row=i//6, column=i%6, padx=10, pady=0.5,sticky="w")
    selected_checkboxes.append((checkbox, var, "tab4")) 

for i , (key,value) in enumerate(app_list_tab5.items()):
    var = tk.IntVar()
    checkbox = ttk.Checkbutton(tab5, text=key, variable=var)
    checkbox.grid(row=i//6, column=i%6, padx=8, pady=2,sticky="w")
    selected_checkboxes.append((checkbox, var, "tab5")) 
    
for i , (key,value) in enumerate(app_list_tab6.items()):
    var = tk.IntVar()
    checkbox = ttk.Checkbutton(tab6, text=key, variable=var)
    checkbox.grid(row=i//3, column=i%3, padx=5, pady=1,sticky="w")
    selected_checkboxes.append((checkbox, var, "tab6"))  
    
for i , (key,value) in enumerate(app_list_tab7.items()):
    var = tk.IntVar()
    checkbox = ttk.Checkbutton(tab7, text=key, variable=var)
    checkbox.grid(row=i//3, column=i%3, padx=5, pady=1,sticky="w")
    selected_checkboxes.append((checkbox, var, "tab7")) 
  
# App Frame
app_frame = ttk.Frame(big_frame)
app_frame.pack()

def apply_changes():
    selected_values = []
    for checkbox,var,tab in selected_checkboxes:
        if var.get():
            if tab == "tab1":
                selected_values.append(app_list_tab1[checkbox["text"]])
            elif tab == "tab2":
                selected_values.append(app_list_tab2[checkbox["text"]])
            elif tab == "tab3":
                selected_values.append(app_list_tab3[checkbox["text"]])
            elif tab == "tab4":
                selected_values.append(app_list_tab4[checkbox["text"]])
            elif tab == "tab5":
                selected_values.append(app_list_tab5[checkbox["text"]])
            elif tab == "tab6":
                selected_values.append(app_list_tab6[checkbox["text"]])
            elif tab == "tab7":
                selected_values.append(app_list_tab7[checkbox["text"]])
    with open("tweaker.bat", "w") as f:
            f.write("@echo off \nif not \"%1\"==\"am_admin\" (powershell start -verb runas '%0' am_admin & exit /b)\n")
            for value in selected_values:
                f.write("%s\n" % value)
    subprocess.run("tweaker.bat", shell=True)
     
# Tab1 buttons
grid_frame = ttk.Frame(tab1)
grid_frame.grid()
grid_frame.columnconfigure(0, minsize=100)
grid_frame.columnconfigure(1, minsize=100)
grid_frame.columnconfigure(2, minsize=100)
grid_frame.columnconfigure(3, minsize=100)

# Tab2 buttons
grid_frame_tab2 = ttk.Frame(tab2)
grid_frame_tab2.grid()
grid_frame_tab2.columnconfigure(0, minsize=100)
grid_frame_tab2.columnconfigure(1, minsize=100)
grid_frame_tab2.columnconfigure(2, minsize=100)
grid_frame_tab2.columnconfigure(3, minsize=100)

# Tab3 buttons
grid_frame_tab3 = ttk.Frame(tab3)
grid_frame_tab3.grid()
grid_frame_tab3.columnconfigure(0, minsize=100)
grid_frame_tab3.columnconfigure(1, minsize=100)
grid_frame_tab3.columnconfigure(2, minsize=100)
grid_frame_tab3.columnconfigure(3, minsize=100)

# Tab4 buttons
grid_frame_tab4 = ttk.Frame(tab4)
grid_frame_tab4.grid()
grid_frame_tab4.columnconfigure(0, minsize=100)
grid_frame_tab4.columnconfigure(1, minsize=100)
grid_frame_tab4.columnconfigure(2, minsize=100)
grid_frame_tab4.columnconfigure(3, minsize=100)

# Tab5 buttons
grid_frame_tab5 = ttk.Frame(tab5)
grid_frame_tab5.grid()
grid_frame_tab5.columnconfigure(0, minsize=100)
grid_frame_tab5.columnconfigure(1, minsize=100)
grid_frame_tab5.columnconfigure(2, minsize=100)
grid_frame_tab5.columnconfigure(3, minsize=100)

# Tab6 buttons
grid_frame_tab6 = ttk.Frame(tab6)
grid_frame_tab6.grid()
grid_frame_tab6.columnconfigure(0, minsize=100)
grid_frame_tab6.columnconfigure(1, minsize=100)
grid_frame_tab6.columnconfigure(2, minsize=100)
grid_frame_tab6.columnconfigure(3, minsize=100)


# Tab7 buttons
grid_frame_tab7 = ttk.Frame(tab7)
grid_frame_tab7.grid()
grid_frame_tab7.columnconfigure(0, minsize=100)
grid_frame_tab7.columnconfigure(1, minsize=100)
grid_frame_tab7.columnconfigure(2, minsize=100)
grid_frame_tab7.columnconfigure(3, minsize=100)

checkboxes = []

buttons_frame = ttk.Frame(root)
buttons_frame.pack()
apply_button = ttk.Button(buttons_frame, text="Apply Changes ✓" , command=apply_changes)
apply_button.grid(row=1, column=0, columnspan=1, padx=20, pady=20)
change_theme_button = ttk.Button(buttons_frame, text="Change Theme 🎨", command=change_theme)
change_theme_button.grid(row=1, column=2, columnspan=1, padx=20, pady=20)

root.mainloop()


