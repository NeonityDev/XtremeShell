using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Packaging;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Net.Http;
using System.Xml.Linq;
using IOPath = System.IO.Path;
using IOFile = System.IO.File;
using System.Runtime.InteropServices;
using Windows.Management.Deployment;
using Windows.ApplicationModel;
using System.IO;



namespace XtremeShell5
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private ObservableCollection<PackageInfo> packages = new ObservableCollection<PackageInfo>();
        private ObservableCollection<PackageInfo> filteredPackages = new ObservableCollection<PackageInfo>();
        private ObservableCollection<PackageItem> _packages = new ObservableCollection<PackageItem>();
        private ObservableCollection<PackageItem> _selectedPackages = new ObservableCollection<PackageItem>();
        private bool _isSearching = false;


        private bool _suppressSearch = true; // block TextChanged logic until we finish loading
        public MainWindow()
        {
            InitializeComponent();
            InitializePackageManager();

            InstallPackageList.ItemsSource = _packages;

            // Show defaults after layout completes
            Dispatcher.BeginInvoke(new Action(() =>
            {
                ShowDefaultPackages();   // fills _packages and collapses empty/loading panels
                _suppressSearch = false; // allow TextChanged logic afterwards
            }), System.Windows.Threading.DispatcherPriority.Loaded);
        }

        private void xsVersion_Click(object sender, RoutedEventArgs e)
        {
            string url = "https://xtremeshell.neonity.hu";
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }

        private async void button_Click(object sender, RoutedEventArgs e)
        {
            bmLog.Text = ("");
            var clickedButton = sender as Button;
            if (clickedButton == null)
                return;

            switch (clickedButton.Name)
            {
                case "bmExit":
                    bmLog.Text = "Thanks for using XtremeShell!";
                    await Task.Delay(500);
                    this.Close();
                    break;

                case "bmReboot":
                    bmLog.Text = "Rebooting...";
                    await Task.Delay(500);
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "shutdown",
                        Arguments = "/r /t 0",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                    break;

                case "bmNeonity":
                    string yt = "https://www.youtube.com/@Neonity";
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = yt,
                        UseShellExecute = true
                    });
                    break;

                case "bmRebootUefi":
                    bmLog.Text = "Rebooting to UEFI...";
                    await Task.Delay(500);
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "shutdown",
                        Arguments = "/r /fw /t 0",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                    break;

                case "UltPwrPl":
                    var psi = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = "powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    Process.Start(psi)?.WaitForExit();
                    bmLog.Text = ("Enabled Ultimate Power Plan.");
                    break;

                case "StickyKeys":
                    StickyKey.Toggle(enable: false);
                    bmLog.Text = ("Disabled Sticky Keys Hotkey.");
                    break;

                case "DisableAds":
                    string baseKey = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps";

                    string[] apps = new string[]
                    {
                "22StokedOnIt.NotebookPro_ffs55s3hze5sr",
                "2FE3CB00.PicsArt-PhotoStudio_crhqpqs3x1ygc",
                "41038Axilesoft.ACGMediaPlayer_wxjjre7dryqb6",
                "5CB722CC.SeekersNotesMysteriesofDarkwood_ypk0bew5psyra",
                "7458BE2C.WorldofTanksBlitz_x4tje2y229k00",
                "828B5831.HiddenCityMysteryofShadows_ytsefhwckbdv6",
                "828B5831.TheSecretSociety-HiddenMystery_ytsefhwckbdv6",
                "89006A2E.AutodeskSketchBook_tf1gferkr813w",
                "9E2F88E3.Twitter_wgeqdkkx372wm",
                "A278AB0D.AsphaltStreetStormRacing_h6adky7gbf63m",
                "A278AB0D.DisneyMagicKingdoms_h6adky7gbf63m",
                "A278AB0D.DragonManiaLegends_h6adky7gbf63m",
                "A278AB0D.MarchofEmpires_h6adky7gbf63m",
                "AdobeSystemsIncorporated.PhotoshopElements2018_ynb6jyjzte8ga",
                "CAF9E577.Plex_aam28m9va5cke",
                "DolbyLaboratories.DolbyAccess_rz1tebttyb220",
                "Drawboard.DrawboardPDF_gqbn7fs4pywxm",
                "Expedia.ExpediaHotelsFlightsCarsActivities_0wbx8rnn4qk5c",
                "Facebook.317180B0BB486_8xx8rvfyw5nnt",
                "Facebook.Facebook_8xx8rvfyw5nnt",
                "Facebook.InstagramBeta_8xx8rvfyw5nnt",
                "Fitbit.FitbitCoach_6mqt6hf9g46tw",
                "flaregamesGmbH.RoyalRevolt2_g0q0z3kw54rap",
                "GAMELOFTSA.Asphalt8Airborne_0pp20fcewvvtj",
                "king.com.BubbleWitch3Saga_kgqvnymyfvs32",
                "king.com.CandyCrushSaga_kgqvnymyfvs32",
                "king.com.CandyCrushSodaSaga_kgqvnymyfvs32",
                "Microsoft.AgeCastles_8wekyb3d8bbwe",
                "Microsoft.BingNews_8wekyb3d8bbwe",
                "Microsoft.BingSports_8wekyb3d8bbwe",
                "Microsoft.BingWeather_8wekyb3d8bbwe",
                "microsoft.microsoftskydrive_8wekyb3d8bbwe",
                "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe",
                "Microsoft.MinecraftUWP_8wekyb3d8bbwe",
                "Microsoft.MSPaint_8wekyb3d8bbwe",
                "NAVER.LINEwin8_8ptj331gd3tyt",
                "Nordcurrent.CookingFever_m9bz608c1b9ra",
                "SiliconBendersLLC.Sketchable_r2kxzpx527qgj",
                "SpotifyAB.SpotifyMusic_zpdnekdrzrea0",
                "ThumbmunkeysLtd.PhototasticCollage_nfy108tqq3p12",
                "USATODAY.USATODAY_wy7mw3214mat8",
                "WinZipComputing.WinZipUniversal_3ykzqggjzj4z0"
                    };

                    try
                    {
                        foreach (string app in apps)
                        {
                            Registry.SetValue(baseKey, app, 0, RegistryValueKind.DWord);
                            bmLog.Text = $"Updated: {app}";
                        }

                        Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                                          "ShowSyncProviderNotifications",
                                          0,
                                          RegistryValueKind.DWord);

                        bmLog.Text = ("Disabled Ads.");
                    }
                    catch (Exception ex)
                    {
                        bmLog.Text = $"Error updating registry: {ex.Message}";
                    }


                    break;

                case "DisableTelemetry":
                    string DisableTelemetryScript = @"
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' | Out-Null
Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' | Out-Null
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'ContentDeliveryAllowed' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'OemPreInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEverEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338387Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338388Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-353698Enabled' -Type DWord -Value 0
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Type DWord -Value 0
reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' /v 'Enabled' /t REG_DWORD /d '0' /f
reg delete 'HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' /v 'Id' /f
";

                    await Task.Run(() =>
                    {
                        try
                        {
                            var psi = new ProcessStartInfo
                            {
                                FileName = "powershell.exe",
                                Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{DisableTelemetryScript}\"",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            };

                            using var process = new Process { StartInfo = psi };
                            process.OutputDataReceived += (s, e) =>
                            {
                                if (!string.IsNullOrEmpty(e.Data))
                                {
                                    Dispatcher.Invoke(() =>
                                    {
                                        bmLog.Text = (e.Data + Environment.NewLine);
                                        bmLog.ScrollToEnd();
                                    });
                                }
                            };
                            process.ErrorDataReceived += (s, e) =>
                            {
                                if (!string.IsNullOrEmpty(e.Data))
                                {
                                    Dispatcher.Invoke(() =>
                                    {
                                        bmLog.AppendText(e.Data + Environment.NewLine);
                                        bmLog.ScrollToEnd();
                                    });
                                }
                            };

                            process.Start();
                            process.BeginOutputReadLine();
                            process.BeginErrorReadLine();
                            process.WaitForExit();

                            Dispatcher.Invoke(() =>
                            {
                                bmLog.Text = "Telemetry disabled.";
                            });
                        }
                        catch (Exception ex)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                bmLog.AppendText("Exception: " + ex.Message + Environment.NewLine);
                                bmLog.ScrollToEnd();
                            });
                        }
                    });
                    break;

                case "CleanReBin":
                    await RecycleBinClear.EmptyAsync();
                    bmLog.Text = ("Cleaned Recycle Bin.");
                    break;

                case "RepairChoco":
                    await Task.Run(() => InstallOrUpgradeChocolateyAsync());
                    break;

                case "DelTmpFls":
                    CleanTempAndPrefetch();
                    bmLog.Text = ("Deleted temporary files.");
                    break;

                case "ApplyUpdatePreset":
                    try
                    {
                        bmLog.Text = "Please wait...";

                        // Create required keys (like New-Item -Force)
                        using (var polWin = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows"))
                        {
                            polWin?.CreateSubKey(@"Device Metadata")?.Dispose();
                            polWin?.CreateSubKey(@"DriverSearching")?.Dispose();
                            polWin?.CreateSubKey(@"WindowsUpdate")?.Dispose();
                            polWin?.CreateSubKey(@"WindowsUpdate\AU")?.Dispose();
                        }

                        // Disable driver updates via WU
                        Registry.SetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                            "ExcludeWUDriversInQualityUpdate",
                            1,
                            RegistryValueKind.DWord);

                        // Defer updates (UX\Settings)
                        Registry.SetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                            "DeferFeatureUpdatesPeriodInDays",
                            365,
                            RegistryValueKind.DWord);

                        // Handle both with/without trailing space (script had a space at the end)
                        Registry.SetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                            "DeferQualityUpdatesPeriodInDays",
                            7,
                            RegistryValueKind.DWord);
                        Registry.SetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                            "DeferQualityUpdatesPeriodInDays ",
                            7,
                            RegistryValueKind.DWord);

                        // No auto reboot with logged-on users
                        Registry.SetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                            "NoAutoRebootWithLoggedOnUsers",
                            1,
                            RegistryValueKind.DWord);

                        // Disable AU power management changes
                        Registry.SetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                            "AUPowerManagement",
                            0,
                            RegistryValueKind.DWord);

                        // Branch readiness
                        Registry.SetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                            "BranchReadinessLevel",
                            20,
                            RegistryValueKind.DWord);

                        // Prevent device metadata from network
                        Registry.SetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
                            "PreventDeviceMetadataFromNetwork",
                            1,
                            RegistryValueKind.DWord);

                        bmLog.Text = "Applied Update optimizations";
                    }
                    catch (Exception ex)
                    {
                        bmLog.Text = "Error: " + ex.Message;
                    }
                    break;

                case "UniEdge":
                    bmLog.Text = ("Please continue in PowerShell");
                    string script = @"
@(set ""0=%~f0""^)
		sp 'HKCU:\Volatile Environment' 'Edge_Removal' @'

$also_remove_webview = 1
write-host ""`nEdge will be completely uninstalled.""
write-host ""`nALERT: You will NOT be able to reinstall Microsoft Edge after running this script!""
$uconfirmation = Read-Host ""`nContinue? [Y/N]""
if ($uconfirmation -ne ""Y"") { exit }
$host.ui.RawUI.WindowTitle = 'XtremeShell Edge Uninstaller '
write-host ""`nStarting... Please wait!""
## targets
$remove_win32 = @(""Microsoft Edge"",""Microsoft Edge Update""); $remove_appx = @(""MicrosoftEdge"")
if ($also_remove_webview -eq 1) {$remove_win32 += ""Microsoft EdgeWebView""; $remove_appx += ""Win32WebViewHost""}
## enable admin privileges
$D1=[uri].module.gettype('System.Diagnostics.Process').""GetM`ethods""(42) |where {$_.Name -eq 'SetPrivilege'} #`:no-ev-warn
'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege'|foreach {$D1.Invoke($null, @(""$_"",2))}
## set useless policies
foreach ($p in 'HKLM\SOFTWARE\Policies','HKLM\SOFTWARE') {
  cmd /c ""reg add """"$p\Microsoft\EdgeUpdate"""" /f /v InstallDefault /d 0 /t reg_dword >nul 2>nul""
  cmd /c ""reg add """"$p\Microsoft\EdgeUpdate"""" /f /v Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062} /d 0 /t reg_dword >nul 2>nul""
  cmd /c ""reg add """"$p\Microsoft\EdgeUpdate"""" /f /v Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} /d 1 /t reg_dword >nul 2>nul""
  cmd /c ""reg add """"$p\Microsoft\EdgeUpdate"""" /f /v DoNotUpdateToEdgeWithChromium /d 1 /t reg_dword >nul 2>nul""
}
## clear win32 uninstall block
foreach ($hk in 'HKCU','HKLM') {foreach ($wow in '','\Wow6432Node') {foreach ($i in $remove_win32) {
  cmd /c ""reg delete """"$hk\SOFTWARE${wow}\Microsoft\Windows\CurrentVersion\Uninstall\$i"""" /f /v NoRemove >nul 2>nul""
}}}
## find all Edge setup.exe and gather BHO paths
$setup = @(); $bho = @(); $bho += ""$env:ProgramData\ie_to_edge_stub.exe""; $bho += ""$env:Public\ie_to_edge_stub.exe""
""LocalApplicationData"",""ProgramFilesX86"",""ProgramFiles"" |foreach {
  $setup += dir $($([Environment]::GetFolderPath($_)) + '\Microsoft\Edge*\setup.exe') -rec -ea 0
  $bho += dir $($([Environment]::GetFolderPath($_)) + '\Microsoft\Edge*\ie_to_edge_stub.exe') -rec -ea 0
}
## shut edge down
foreach ($p in 'MicrosoftEdgeUpdate','chredge','msedge','edge','msedgewebview2','Widgets') { kill -name $p -force -ea 0 }
## use dedicated C:\Scripts path due to Sigma rules FUD
$DIR = ""$env:SystemDrive\Scripts""; $null = mkdir $DIR -ea 0
## export OpenWebSearch innovative redirector
foreach ($b in $bho) { if (test-path $b) { try {copy $b ""$DIR\ie_to_edge_stub.exe"" -force -ea 0} catch{} } }
## clear appx uninstall block and remove
$provisioned = get-appxprovisionedpackage -online; $appxpackage = get-appxpackage -allusers
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'; $store_reg = $store.replace(':','')
$users = @('S-1-5-18'); if (test-path $store) {$users += $((dir $store |where {$_ -like '*S-1-5-21*'}).PSChildName)}
foreach ($choice in $remove_appx) { if ('' -eq $choice.Trim()) {continue}
  foreach ($appx in $($provisioned |where {$_.PackageName -like ""*$choice*""})) {
    $PackageFamilyName = ($appxpackage |where {$_.Name -eq $appx.DisplayName}).PackageFamilyName; $PackageFamilyName
    cmd /c ""reg add """"$store_reg\Deprovisioned\$PackageFamilyName"""" /f >nul 2>nul""
    cmd /c ""dism /online /remove-provisionedappxpackage /packagename:$($appx.PackageName) >nul 2>nul""
    #powershell -nop -c remove-appxprovisionedpackage -packagename ""'$($appx.PackageName)'"" -online 2>&1 >''
  }
  foreach ($appx in $($appxpackage |where {$_.PackageFullName -like ""*$choice*""})) {
    $inbox = (gp ""$store\InboxApplications\*$($appx.Name)*"" Path).PSChildName
    $PackageFamilyName = $appx.PackageFamilyName; $PackageFullName = $appx.PackageFullName; $PackageFullName
    foreach ($app in $inbox) {cmd /c ""reg delete """"$store_reg\InboxApplications\$app"""" /f >nul 2>nul"" }
    cmd /c ""reg add """"$store_reg\Deprovisioned\$PackageFamilyName"""" /f >nul 2>nul""
    foreach ($sid in $users) {cmd /c ""reg add """"$store_reg\EndOfLife\$sid\$PackageFullName"""" /f >nul 2>nul""}
    cmd /c ""dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >nul 2>nul""
    powershell -nop -c ""remove-appxpackage -package '$PackageFullName' -AllUsers"" 2>&1 >''
    foreach ($sid in $users) {cmd /c ""reg delete """"$store_reg\EndOfLife\$sid\$PackageFullName"""" /f >nul 2>nul""}
  }
}
## shut edge down, again
foreach ($p in 'MicrosoftEdgeUpdate','chredge','msedge','edge','msedgewebview2','Widgets') { kill -name $p -force -ea 0 }
## brute-run found Edge setup.exe with uninstall args
$purge = '--uninstall --system-level --force-uninstall'
if ($also_remove_webview -eq 1) { foreach ($s in $setup) { try{ start -wait $s -args ""--msedgewebview $purge"" } catch{} } }
foreach ($s in $setup) { try{ start -wait $s -args ""--msedge $purge"" } catch{} }
## prevent latest cumulative update (LCU) failing due to non-matching EndOfLife Edge entries
foreach ($i in $remove_appx) {
  dir ""$store\EndOfLife"" -rec -ea 0 |where {$_ -like ""*${i}*""} |foreach {cmd /c ""reg delete """"$($_.Name)"""" /f >nul 2>nul""}
  dir ""$store\Deleted\EndOfLife"" -rec -ea 0 |where {$_ -like ""*${i}*""} |foreach {cmd /c ""reg delete """"$($_.Name)"""" /f >nul 2>nul""}
}
## extra cleanup
$desktop = $([Environment]::GetFolderPath('Desktop')); $appdata = $([Environment]::GetFolderPath('ApplicationData'))
del ""$appdata\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Tombstones\Microsoft Edge.lnk"" -force -ea 0
del ""$appdata\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk"" -force -ea 0
del ""$desktop\Microsoft Edge.lnk"" -force -ea 0

## add OpenWebSearch to redirect microsoft-edge: anti-competitive links to the default browser
$IFEO = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$MSEP = ($env:ProgramFiles,${env:ProgramFiles(x86)})[[Environment]::Is64BitOperatingSystem] + '\Microsoft\Edge\Application'
$MIN = ('--headless','--width 1 --height 1')[([environment]::OSVersion.Version.Build) -gt 25179]
$CMD = ""$env:systemroot\system32\conhost.exe $MIN"" # AveYo: minimize prompt - see Terminal issue #13914
cmd /c ""reg add HKCR\microsoft-edge /f /ve /d URL:microsoft-edge >nul""
cmd /c ""reg add HKCR\microsoft-edge /f /v """"URL Protocol"""" /d """""""" >nul""
cmd /c ""reg add HKCR\microsoft-edge /f /v NoOpenWith /d """""""" >nul""
cmd /c ""reg add HKCR\microsoft-edge\shell\open\command /f /ve /d """"$DIR\ie_to_edge_stub.exe %1"""" >nul""
cmd /c ""reg add HKCR\MSEdgeHTM /f /v NoOpenWith /d """""""" >nul""
cmd /c ""reg add HKCR\MSEdgeHTM\shell\open\command /f /ve /d """"$DIR\ie_to_edge_stub.exe %1"""" >nul""
cmd /c ""reg add """"$IFEO\ie_to_edge_stub.exe"""" /f /v UseFilter /d 1 /t reg_dword >nul >nul""
cmd /c ""reg add """"$IFEO\ie_to_edge_stub.exe\0"""" /f /v FilterFullPath /d """"$DIR\ie_to_edge_stub.exe"""" >nul""
cmd /c ""reg add """"$IFEO\ie_to_edge_stub.exe\0"""" /f /v Debugger /d """"$CMD $DIR\OpenWebSearch.cmd"""" >nul""
cmd /c ""reg add """"$IFEO\msedge.exe"""" /f /v UseFilter /d 1 /t reg_dword >nul""
cmd /c ""reg add """"$IFEO\msedge.exe\0"""" /f /v FilterFullPath /d """"$MSEP\msedge.exe"""" >nul""
cmd /c ""reg add """"$IFEO\msedge.exe\0"""" /f /v Debugger /d """"$CMD $DIR\OpenWebSearch.cmd"""" >nul""

$OpenWebSearch = @$
@title OpenWebSearch Redux & echo off & set ?= open start menu web search, widgets links or help in your chosen browser
for /f %%E in ('""prompt $E$S& for %%e in (1) do rem""') do echo;%%E[2t 2>nul & rem AveYo: minimize prompt
call :reg_var ""HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice"" ProgID ProgID
if /i ""%ProgID%"" equ ""MSEdgeHTM"" echo;Default browser is set to Edge! Change it or remove OpenWebSearch script. & pause & exit /b
call :reg_var ""HKCR\%ProgID%\shell\open\command"" """" Browser
set Choice=& for %%. in (%Browser%) do if not defined Choice set ""Choice=%%~.""
call :reg_var ""HKCR\MSEdgeMHT\shell\open\command"" """" FallBack
set ""Edge="" & for %%. in (%FallBack%) do if not defined Edge set ""Edge=%%~.""
set ""URI="" & set ""URL="" & set ""NOOP="" & set ""PassTrough=%Edge:msedge=edge%""
set ""CLI=%CMDCMDLINE:""=``% ""
if defined CLI set ""CLI=%CLI:*ie_to_edge_stub.exe`` =%""
if defined CLI set ""CLI=%CLI:*ie_to_edge_stub.exe =%""
if defined CLI set ""CLI=%CLI:*msedge.exe`` =%""
if defined CLI set ""CLI=%CLI:*msedge.exe =%""
set ""FIX=%CLI:~-1%""
if defined CLI if ""%FIX%""=="" "" set ""CLI=%CLI:~0,-1%""
if defined CLI set ""RED=%CLI:microsoft-edge=%""
if defined CLI set ""URL=%CLI:http=%""
if defined CLI set ""ARG=%CLI:``=""%""
if ""%CLI%"" equ ""%RED%"" (set NOOP=1) else if ""%CLI%"" equ ""%URL%"" (set NOOP=1)
if defined NOOP if exist ""%PassTrough%"" start """" ""%PassTrough%"" %ARG%
if defined NOOP exit /b
set ""URL=%CLI:*microsoft-edge=%""
set ""URL=http%URL:*http=%""
set ""FIX=%URL:~-2%""
if defined URL if ""%FIX%""==""``"" set ""URL=%URL:~0,-2%""
call :dec_url
start """" ""%Choice%"" ""%URL%""
exit

:reg_var [USAGE] call :reg_var ""HKCU\Volatile Environment"" value-or-"""" variable [extra options]
set {var}=& set {reg}=reg query ""%~1"" /v %2 /z /se "","" /f /e& if %2=="""" set {reg}=reg query ""%~1"" /ve /z /se "","" /f /e
for /f ""skip=2 tokens=* delims="" %%V in ('%{reg}% %4 %5 %6 %7 %8 %9 2^>nul') do if not defined {var} set ""{var}=%%V""
if not defined {var} (set {reg}=& set ""%~3=""& exit /b) else if %2=="""" set ""{var}=%{var}:*)    =%""& rem AveYo: v3
if not defined {var} (set {reg}=& set ""%~3=""& exit /b) else set {reg}=& set ""%~3=%{var}:*)    =%""& set {var}=& exit /b

:dec_url brute url percent decoding  
set "".=%URL:!=}%""&setlocal enabledelayedexpansion& rem brute url percent decoding
set "".=!.:%%={!"" &set "".=!.:{3A=:!"" &set "".=!.:{2F=/!"" &set "".=!.:{3F=?!"" &set "".=!.:{23=#!"" &set "".=!.:{5B=[!"" &set "".=!.:{5D=]!""
set "".=!.:{40=@!""&set "".=!.:{21=}!"" &set "".=!.:{24=$!"" &set "".=!.:{26=&!"" &set "".=!.:{27='!"" &set "".=!.:{28=(!"" &set "".=!.:{29=)!""
set "".=!.:{2A=*!""&set "".=!.:{2B=+!"" &set "".=!.:{2C=,!"" &set "".=!.:{3B=;!"" &set "".=!.:{3D==!"" &set "".=!.:{25=%%!""&set "".=!.:{20= !""
set "".=!.:{=%%!"" &rem set "",=!.:%%=!"" & if ""!,!"" neq ""!.!"" endlocal& set ""URL=%.:}=!%"" & call :dec_url
endlocal& set ""URL=%.:}=!%"" & exit /b
rem done

$@
[io.file]::WriteAllText(""$DIR\OpenWebSearch.cmd"", $OpenWebSearch) >''
## cleanup
$cleanup = gp 'Registry::HKEY_Users\S-1-5-21*\Volatile*' Edge_Removal -ea 0
if ($cleanup) {rp $cleanup.PSPath Edge_Removal -force -ea 0}

write-host -nonew -fore green -back black ""`n EDGE REMOVED!""; 
exit

## ask to run script as admin
'@.replace(""$@"", ""'@"").replace(""@$"", ""@'"") -force -ea 0;
		$A = '-nop -noe -c & {iex((gp ''Registry::HKEY_Users\S-1-5-21*\Volatile*'' Edge_Removal -ea 0)[0].Edge_Removal)}'
		start powershell -args $A -verb runas
		$_Press_Enter
";

                    byte[] scriptBytes = Encoding.Unicode.GetBytes(script);

                    string base64Script = Convert.ToBase64String(scriptBytes);

                    var stickyPsi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {base64Script}",
                        UseShellExecute = true,
                        Verb = "runas",
                        WindowStyle = ProcessWindowStyle.Normal
                    };

                    try
                    {
                        Process.Start(stickyPsi);
                    }
                    catch (Exception ex)
                    {
                        bmLog.Text = ("PowerShell execution failed or cancelled: " + ex.Message);
                    }
                    break;

                case "installEdge":
                    string UndoEdgeScript = @"
				Remove-Item -Path ""HKCR:\microsoft-edge"" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path ""HKCR:\MSEdgeHTM"" -Recurse -Force -ErrorAction SilentlyContinue
	
	$ifeoPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ie_to_edge_stub.exe',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe'
)
foreach ($path in $ifeoPaths)
{
    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
}
	
	$fakeStub = Join-Path $env:SystemDrive ""Scripts\ie_to_edge_stub.exe""

	if (Test-Path $fakeStub)
	{
		Remove-Item $fakeStub -Force -ErrorAction SilentlyContinue
	}
";

                    await Task.Run(() =>
                    {
                        try
                        {
                            var psi = new ProcessStartInfo
                            {
                                FileName = "powershell.exe",
                                Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{UndoEdgeScript}\"",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            };

                            using var process = new Process { StartInfo = psi };
                            process.OutputDataReceived += (s, e) =>
                            {
                                if (!string.IsNullOrEmpty(e.Data))
                                {
                                    Dispatcher.Invoke(() =>
                                    {
                                        bmLog.Text = (e.Data + Environment.NewLine);
                                        bmLog.ScrollToEnd();
                                    });
                                }
                            };
                            process.ErrorDataReceived += (s, e) =>
                            {
                                if (!string.IsNullOrEmpty(e.Data))
                                {
                                    Dispatcher.Invoke(() =>
                                    {
                                        bmLog.AppendText(e.Data + Environment.NewLine);
                                        bmLog.ScrollToEnd();
                                    });
                                }
                            };

                            process.Start();
                            process.BeginOutputReadLine();
                            process.BeginErrorReadLine();
                            process.WaitForExit();
                        }
                        catch (Exception ex)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                bmLog.AppendText("Exception: " + ex.Message + Environment.NewLine);
                                bmLog.ScrollToEnd();
                            });
                        }
                    });
                    bmLog.Text = "Removed Microsoft Edge redirections, Edge can be reinstalled.";
                    break;

                case "installVencord":
                    await InstallVencordAsync();
                    break;

                default:
                    bmLog.Text = $"[Error] No handler for button: {clickedButton.Name}";
                    break;
            }
        }

        private async Task InstallVencordAsync()
        {
            string url = "https://github.com/Vencord/Installer/releases/latest/download/VencordInstaller.exe";
            string installerPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Downloads",
                "vencord-installer.exe"
            );

            try
            {
                bmLog.Text = "Downloading Vencord installer executable...";

                using (var http = new HttpClient())
                using (var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead))
                {
                    response.EnsureSuccessStatusCode();

                    var total = response.Content.Headers.ContentLength;
                    using (var input = await response.Content.ReadAsStreamAsync())
                    using (var output = new FileStream(installerPath, FileMode.Create, FileAccess.Write, FileShare.None, 8192, useAsync: true))
                    {
                        var buffer = new byte[8192];
                        long totalRead = 0;
                        int read;
                        while ((read = await input.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            await output.WriteAsync(buffer, 0, read);
                            totalRead += read;

                            if (total.HasValue)
                            {
                                var pct = (int)(totalRead * 100 / total.Value);
                                bmLog.Text = $"Downloading Vencord installer executable... {pct}%";
                            }
                        }
                    }
                }

                if (!File.Exists(installerPath))
                {
                    bmLog.Text = "ERROR: Failed to download the installer.";
                    return;
                }

                bmLog.Text = "Download complete. Running the installer...";

                var tcs = new TaskCompletionSource<int>();
                var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = installerPath,
                        Arguments = "/S",               // silent install
                        UseShellExecute = true,         // lets UAC prompt if needed
                        WindowStyle = ProcessWindowStyle.Hidden
                    },
                    EnableRaisingEvents = true
                };

                proc.Exited += (s, e) =>
                {
                    tcs.TrySetResult(proc.ExitCode);
                    proc.Dispose();
                };

                if (!proc.Start())
                {
                    bmLog.Text = "ERROR: Could not start the installer.";
                    return;
                }

                int exitCode = await tcs.Task;

                bmLog.Text = exitCode == 0
                    ? "Vencord installed successfully."
                    : $"Installer finished with exit code {exitCode}.";
            }
            catch (Exception ex)
            {
                bmLog.Text = $"ERROR: {ex.Message}";
            }
        }

        private void AppendLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                bmLog.Text = "Starting to delete temporary files...";
            });
        }

        private void DeleteFolderContents(string folderPath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(folderPath) || !Directory.Exists(folderPath))
                {
                    AppendLog($"Skip: '{folderPath}' does not exist.");
                    return;
                }

                AppendLog($"Cleaning: {folderPath}");

                // Delete files
                foreach (var file in Directory.EnumerateFiles(folderPath, "*", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        // Make sure file isn't read-only/system/hidden
                        File.SetAttributes(file, FileAttributes.Normal);
                        File.Delete(file);
                    }
                    catch (Exception ex)
                    {
                        AppendLog($"  File in use/locked: {IOPath.GetFileName(file)} — {ex.Message}");
                    }
                }

                // Delete subfolders
                foreach (var dir in Directory.EnumerateDirectories(folderPath, "*", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        // Clear attributes on all children before removal
                        ClearAttributesRecursively(dir);
                        Directory.Delete(dir, recursive: true);
                    }
                    catch (Exception ex)
                    {
                        AppendLog($"  Folder locked: {IOPath.GetFileName(dir)} — {ex.Message}");
                    }
                }

                AppendLog($"Done: {folderPath}");
            }
            catch (Exception ex)
            {
                AppendLog($"Error on '{folderPath}': {ex.Message}");
            }
        }

        private void ClearAttributesRecursively(string path)
        {
            // Normalize attributes so deletion won't fail on Hidden/System/ReadOnly
            foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try { File.SetAttributes(f, FileAttributes.Normal); } catch { /* ignore */ }
            }
            foreach (var d in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories))
            {
                try { File.SetAttributes(d, FileAttributes.Normal); } catch { /* ignore */ }
            }
            try { File.SetAttributes(path, FileAttributes.Normal); } catch { /* ignore */ }
        }

        private void CleanTempAndPrefetch()
        {
            // %TEMP% (user)
            string userTemp = IOPath.GetTempPath();

            // C:\Windows\Temp
            string winTemp = IOPath.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");

            // C:\Windows\Prefetch
            string prefetch = IOPath.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

            AppendLog("Starting cleanup...");

            DeleteFolderContents(userTemp);
            DeleteFolderContents(winTemp);
            DeleteFolderContents(prefetch);

            AppendLog("Cleanup finished.");
        }




        static class StickyKey
        {
            [DllImport("user32.dll", SetLastError = true)]
            static extern bool SystemParametersInfo(uint uiAction, uint uiParam, ref STICKYKEYS pvParam, uint fWinIni);

            const uint SPI_GETSTICKYKEYS = 0x003A;
            const uint SPI_SETSTICKYKEYS = 0x003B;
            const uint SPIF_UPDATEINIFILE = 0x01;
            const uint SPIF_SENDCHANGE = 0x02;

            const uint SKF_STICKYKEYSON = 0x00000001;
            const uint SKF_HOTKEYACTIVE = 0x00000004;
            const uint SKF_CONFIRMHOTKEY = 0x00000008;

            [StructLayout(LayoutKind.Sequential)]
            struct STICKYKEYS
            {
                public uint cbSize;
                public uint dwFlags;
            }

            


            public static void Toggle(bool enable)
            {
                var sk = new STICKYKEYS { cbSize = (uint)Marshal.SizeOf(typeof(STICKYKEYS)) };

                SystemParametersInfo(SPI_GETSTICKYKEYS, sk.cbSize, ref sk, 0);

                if (enable)
                {
                    sk.dwFlags |= SKF_STICKYKEYSON | SKF_HOTKEYACTIVE;
                    sk.dwFlags &= ~SKF_CONFIRMHOTKEY;
                }
                else
                {
                    sk.dwFlags &= ~SKF_STICKYKEYSON;
                    sk.dwFlags &= ~(SKF_HOTKEYACTIVE | SKF_CONFIRMHOTKEY);
                }

                SystemParametersInfo(SPI_SETSTICKYKEYS, sk.cbSize, ref sk, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            }
        }

        private void DoEvents()
        {
            Application.Current.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new Action(delegate { }));
        }

        /// <summary>
        /// Remove Apps
        /// </summary>

        private void InitializePackageManager()
        {
            // Initialize collections if not already done
            if (packages == null) packages = new ObservableCollection<PackageInfo>();
            if (filteredPackages == null) filteredPackages = new ObservableCollection<PackageInfo>();

            if (PackageList != null)
            {
                PackageList.ItemsSource = filteredPackages;
                LoadPackagesAsync();

                // Subscribe to selection changes
                packages.CollectionChanged += (s, e) => UpdateSelectionCount();

                // Handle search placeholder visibility
                if (SearchTextBox != null && SearchPlaceholder != null)
                {
                    SearchTextBox.GotFocus += (s, e) => SearchPlaceholder.Visibility = Visibility.Collapsed;
                    SearchTextBox.LostFocus += (s, e) =>
                    {
                        if (string.IsNullOrEmpty(SearchTextBox.Text))
                            SearchPlaceholder.Visibility = Visibility.Visible;
                    };

                    // Initial placeholder state
                    SearchPlaceholder.Visibility = string.IsNullOrEmpty(SearchTextBox.Text) ?
                        Visibility.Visible : Visibility.Collapsed;
                }
            }
        }

        private async void LoadPackagesAsync()
        {
            LoadingPanel.Visibility = Visibility.Visible;
            PackageCountText.Text = "(Loading...)";

            await Task.Run(() =>
            {
                var installedPrograms = new List<PackageInfo>();

                try
                {
                    // Win32 (HKLM + HKCU)
                    installedPrograms.AddRange(EnumerateWin32FromRegistry());

                    // UWP / Store apps (current user)
                    installedPrograms.AddRange(EnumerateUwpPackages());

                    // Optional: de-dupe by DisplayName + Version
                    installedPrograms = installedPrograms
                        .GroupBy(p => (p.DisplayName ?? "").Trim() + "|" + (p.Version ?? ""))
                        .Select(g => g.First())
                        .ToList();
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() =>
                        MessageBox.Show($"Error loading packages: {ex.Message}", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error));
                }

                Dispatcher.Invoke(() =>
                {
                    packages.Clear();
                    foreach (var program in installedPrograms.OrderBy(p => p.DisplayName))
                    {
                        program.PropertyChanged += (s, e) =>
                        {
                            if (e.PropertyName == nameof(PackageInfo.IsSelected))
                                UpdateSelectionCount();
                        };
                        packages.Add(program);
                    }

                    ApplySearchFilter();
                    LoadingPanel.Visibility = Visibility.Collapsed;
                    UpdateSelectionCount();
                });
            });

        }


        private void ApplySearchFilter()
        {
            if (SearchTextBox == null || filteredPackages == null || packages == null) return;

            var searchText = SearchTextBox.Text?.ToLower().Trim() ?? "";

            // Debug output
            System.Diagnostics.Debug.WriteLine($"ApplySearchFilter called with: '{searchText}'");
            System.Diagnostics.Debug.WriteLine($"Total packages: {packages.Count}");

            // Apply filter and get results
            IEnumerable<PackageInfo> filtered;
            if (string.IsNullOrEmpty(searchText))
            {
                filtered = packages;
            }
            else
            {
                filtered = packages.Where(p => (p.DisplayName?.ToLower().Contains(searchText) == true) ||
                                             (p.Publisher?.ToLower().Contains(searchText) == true));
            }

            var filteredList = filtered.ToList();
            System.Diagnostics.Debug.WriteLine($"Filtered results: {filteredList.Count}");

            // Update the filtered collection on UI thread
            Dispatcher.Invoke(() =>
            {
                // Try a more aggressive refresh approach
                var itemsSource = PackageList.ItemsSource;
                PackageList.ItemsSource = null;

                filteredPackages.Clear();
                foreach (var package in filteredList)
                {
                    filteredPackages.Add(package);
                    System.Diagnostics.Debug.WriteLine($"Added: {package.DisplayName}");
                }

                PackageList.ItemsSource = filteredPackages;
                PackageList.Items.Refresh();
            });

            // Update count display
            if (PackageCountText != null)
            {
                var totalCount = packages.Count;
                var filteredCount = filteredPackages.Count;
                PackageCountText.Text = string.IsNullOrEmpty(searchText)
                    ? $"({totalCount} applications)"
                    : $"({filteredCount} of {totalCount} applications)";
            }

            System.Diagnostics.Debug.WriteLine($"Final filtered count: {filteredPackages.Count}");
        }

        private void UpdateSelectionCount()
        {
            var selectedCount = filteredPackages.Count(p => p.IsSelected);
            var totalSelected = packages.Count(p => p.IsSelected);
            SelectedCountText.Text = $"{totalSelected} selected";
            RemoveButton.IsEnabled = totalSelected > 0;

            // Update button styling based on enabled state
            if (selectedCount > 0)
            {
                RemoveButtonBorder.Background = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#8B2635"));
                RemoveButtonBorder.BorderBrush = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#A53D4A"));
                RemoveButton.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.White);
                RemoveButtonBorder.Opacity = 1.0;
            }
            else
            {
                RemoveButtonBorder.Background = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#6A4A4A"));
                RemoveButtonBorder.BorderBrush = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#7A5A5A"));
                RemoveButton.Foreground = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#CCCCCC"));
                RemoveButtonBorder.Opacity = 0.7;
            }

            // Update Select All checkbox state
            var totalPackages = packages.Count;
            if (totalSelected == 0)
                SelectAllCheckBox.IsChecked = false;
            else if (totalSelected == totalPackages)
                SelectAllCheckBox.IsChecked = true;
            else
                SelectAllCheckBox.IsChecked = null; // Indeterminate
        }

        private void SelectAllCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            foreach (var package in filteredPackages)
                package.IsSelected = true;
        }

        private void SelectAllCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            foreach (var package in filteredPackages)
                package.IsSelected = false;
        }

        private void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            LoadPackagesAsync();
        }

        private void SearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ApplySearchFilter();
            UpdateSelectionCount();

            if (SearchPlaceholder != null && SearchTextBox != null)
            {
                SearchPlaceholder.Visibility = string.IsNullOrEmpty(SearchTextBox.Text) ?
                    Visibility.Visible : Visibility.Collapsed;
            }
        }

        private async void RemoveButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedPackages = packages.Where(p => p.IsSelected).ToList();

            if (selectedPackages.Count == 0)
            {
                MessageBox.Show("No applications selected for removal.", "Information",
                              MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var result = MessageBox.Show(
                $"Are you sure you want to uninstall {selectedPackages.Count} selected application(s)?\n\n" +
                "This action cannot be undone.",
                "Confirm Uninstall",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes)
                return;

            RemoveButton.IsEnabled = false;
            var originalText = RemoveButton.Content?.ToString() ?? "Remove";
            RemoveButton.Content = "⏳ Removing...";

            try
            {
                await Task.Run(() =>
                {
                    foreach (var package in selectedPackages)
                    {
                        try
                        {
                            if (package.Type == PackageType.Uwp && !string.IsNullOrWhiteSpace(package.PackageFullName))
                            {
                                // Call the async WinRT removal from this background thread
                                UninstallUwpAsync(package).GetAwaiter().GetResult();
                            }
                            else if (!string.IsNullOrEmpty(package.UninstallString))
                            {
                                // ====== Win32 ======
                                var uninstallCmd = package.UninstallString;
                                if (uninstallCmd.StartsWith("MsiExec.exe", StringComparison.OrdinalIgnoreCase) ||
                                    uninstallCmd.StartsWith("msiexec", StringComparison.OrdinalIgnoreCase))
                                {
                                    var args = uninstallCmd
                                        .Replace("MsiExec.exe", "", StringComparison.OrdinalIgnoreCase)
                                        .Replace("msiexec", "", StringComparison.OrdinalIgnoreCase)
                                        .Trim();

                                    if (args.Contains("/I ", StringComparison.OrdinalIgnoreCase))
                                        args = args.Replace("/I", "/X", StringComparison.OrdinalIgnoreCase);
                                    else if (!args.Contains("/X", StringComparison.OrdinalIgnoreCase))
                                        args = "/X " + args;

                                    args += " /quiet /norestart";

                                    var process = Process.Start(new ProcessStartInfo
                                    {
                                        FileName = "msiexec.exe",
                                        Arguments = args,
                                        UseShellExecute = false,
                                        CreateNoWindow = true
                                    });
                                    process?.WaitForExit(30000); // 30s
                                }
                                else
                                {
                                    var executableCmd = package.UninstallString.Trim();
                                    string fileName;
                                    string arguments = "";

                                    if (executableCmd.StartsWith("\""))
                                    {
                                        var endQuoteIndex = executableCmd.IndexOf("\"", 1);
                                        if (endQuoteIndex > 0)
                                        {
                                            fileName = executableCmd.Substring(1, endQuoteIndex - 1);
                                            if (executableCmd.Length > endQuoteIndex + 1)
                                                arguments = executableCmd[(endQuoteIndex + 1)..].Trim() + " /S /silent";
                                            else
                                                arguments = "/S /silent";
                                        }
                                        else
                                        {
                                            fileName = executableCmd.Trim('"');
                                            arguments = "/S /silent";
                                        }
                                    }
                                    else
                                    {
                                        var exeIndex = executableCmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                                        if (exeIndex > 0)
                                        {
                                            fileName = executableCmd.Substring(0, exeIndex + 4);
                                            if (executableCmd.Length > exeIndex + 4)
                                                arguments = executableCmd[(exeIndex + 4)..].Trim() + " /S /silent";
                                            else
                                                arguments = "/S /silent";
                                        }
                                        else
                                        {
                                            fileName = executableCmd;
                                            arguments = "/S /silent";
                                        }
                                    }

                                    System.Diagnostics.Debug.WriteLine($"Executing: '{fileName}' with args: '{arguments}'");

                                    var process = Process.Start(new ProcessStartInfo
                                    {
                                        FileName = fileName,
                                        Arguments = arguments,
                                        UseShellExecute = false,
                                        CreateNoWindow = true
                                    });
                                    process?.WaitForExit(30000); // 30s
                                }
                                // ====== end existing Win32 logic ======
                            }
                            else
                            {
                                // Nothing actionable found for this entry
                                Dispatcher.Invoke(() =>
                                {
                                    MessageBox.Show($"No uninstall method for {package.DisplayName}.",
                                        "Uninstall", MessageBoxButton.OK, MessageBoxImage.Information);
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                MessageBox.Show($"Failed to uninstall {package.DisplayName}: {ex.Message}",
                                              "Uninstall Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                            });
                        }
                    }
                });

                // Refresh the list
                LoadPackagesAsync();
            }
            finally
            {
                RemoveButton.Content = originalText;
                RemoveButton.IsEnabled = true;
            }
        }




        /// <summary>
        /// Package Store
        /// </summary>
        /// 

        // Default packages
        private readonly List<PackageItem> _defaultPackages = new()
        {
    new PackageItem { Title = "brave",              Version = "", Summary = "Brave Browser",        Authors = "Brave Software, Inc."},
    new PackageItem { Title = "discord",            Version = "", Summary = "Discord Desktop",      Authors = "Discord Inc."},
    new PackageItem { Title = "epicgameslauncher",  Version = "", Summary = "Epic Games Launcher",  Authors = "Epic Games"},
    new PackageItem { Title = "firefox",            Version = "", Summary = "Firefox",              Authors = "Mozilla Foundation"},
    new PackageItem { Title = "git",                Version = "", Summary = "Git",                  Authors = "Git SCM Team"},
    new PackageItem { Title = "hwinfo",             Version = "", Summary = "HWiNFO",               Authors = "Martin Malik"},
    new PackageItem { Title = "spotify",            Version = "", Summary = "Spotify",              Authors = "Spotify AB"},
    new PackageItem { Title = "steam",              Version = "", Summary = "Steam",                Authors = "Valve Corporation"},
    new PackageItem { Title = "vlc",                Version = "", Summary = "VLC Media Player",     Authors = "VideoLAN"},
    new PackageItem { Title = "vscodium",           Version = "", Summary = "VSCodium",             Authors = "VSCodium Community"},
    new PackageItem { Title = "winscp",             Version = "", Summary = "WinSCP",               Authors = "Martin Přikryl"},
};

        private void ShowDefaultPackages()
        {
            _packages.Clear();
            _selectedPackages.Clear();
            foreach (var p in _defaultPackages)
            {
                _packages.Add(new PackageItem
                {
                    Title = p.Summary,
                    Version = p.Version,
                    Authors = p.Authors,
                    ButtonText = "Select",
                    IsButtonEnabled = true,
                    IsSelected = false
                });
            }

            InstallPackageCountText.Text = $"{_packages.Count} recommended packages";
            InstallEmptyStatePanel.Visibility = _packages.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            InstallLoadingPanel.Visibility = Visibility.Collapsed;
            UpdateSelectedCount();
        }


        private CancellationTokenSource _searchCts;

        private async void InstallSearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_suppressSearch)
            {
                InstallSearchPlaceholder.Visibility = string.IsNullOrWhiteSpace(InstallSearchTextBox.Text)
                    ? Visibility.Visible : Visibility.Collapsed;
                return;
            }

            InstallSearchPlaceholder.Visibility = string.IsNullOrWhiteSpace(InstallSearchTextBox.Text)
                ? Visibility.Visible
                : Visibility.Collapsed;

            _searchCts?.Cancel();
            _searchCts = new CancellationTokenSource();
            var token = _searchCts.Token;
            var query = InstallSearchTextBox.Text.Trim();

            try
            {
                await Task.Delay(300, token);

                if (!token.IsCancellationRequested && string.IsNullOrEmpty(query))
                {
                    ShowDefaultPackages();   // show defaults when empty
                    return;
                }

                if (!token.IsCancellationRequested && !string.IsNullOrEmpty(query))
                {
                    await SearchPackagesAsync(query);
                }
            }
            catch (TaskCanceledException) { }
        }


        private static void UninstallWin32(PackageInfo package)
{
    if (string.IsNullOrWhiteSpace(package.UninstallString)) return;

    var uninstallCmd = package.UninstallString.Trim();

    if (uninstallCmd.StartsWith("MsiExec.exe", StringComparison.OrdinalIgnoreCase) ||
        uninstallCmd.StartsWith("msiexec", StringComparison.OrdinalIgnoreCase))
    {
        var args = uninstallCmd.Replace("MsiExec.exe", "", StringComparison.OrdinalIgnoreCase)
                               .Replace("msiexec", "", StringComparison.OrdinalIgnoreCase)
                               .Trim();
        if (args.Contains("/I ", StringComparison.OrdinalIgnoreCase))
            args = args.Replace("/I", "/X", StringComparison.OrdinalIgnoreCase);
        else if (!args.Contains("/X", StringComparison.OrdinalIgnoreCase))
            args = "/X " + args;

        args += " /quiet /norestart";

        using var p = Process.Start(new ProcessStartInfo
        {
            FileName = "msiexec.exe",
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true
        });
        p?.WaitForExit(30000);
        return;
    }
    ParseExeAndRun(uninstallCmd, " /S /silent");
}

private static void ParseExeAndRun(string command, string extraArgs)
{
    string fileName, arguments = "";
    var cmd = command.Trim();

    if (cmd.StartsWith("\""))
    {
        var end = cmd.IndexOf("\"", 1);
        fileName = end > 0 ? cmd.Substring(1, end - 1) : cmd.Trim('"');
        if (end > 0 && cmd.Length > end + 1) arguments = cmd[(end + 1)..].Trim();
    }
    else
    {
        var exeIndex = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIndex > 0)
        {
            fileName = cmd.Substring(0, exeIndex + 4);
            if (cmd.Length > exeIndex + 4) arguments = cmd[(exeIndex + 4)..].Trim();
        }
        else
        {
            fileName = cmd; // hope for the best
        }
    }

    if (!string.IsNullOrEmpty(extraArgs))
        arguments = (arguments + " " + extraArgs).Trim();

    using var p = Process.Start(new ProcessStartInfo
    {
        FileName = fileName,
        Arguments = arguments,
        UseShellExecute = false,
        CreateNoWindow = true
    });
    p?.WaitForExit(30000);
}


        private static List<PackageInfo> EnumerateWin32FromRegistry()
        {
            var list = new List<PackageInfo>();

            var hives = new (RegistryHive hive, RegistryView view)[]
            {
        (RegistryHive.LocalMachine, RegistryView.Registry64),
        (RegistryHive.LocalMachine, RegistryView.Registry32),
        (RegistryHive.CurrentUser, RegistryView.Registry64),
        (RegistryHive.CurrentUser, RegistryView.Registry32),
            };

            foreach (var (hive, view) in hives)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var uninstallKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    if (uninstallKey == null) continue;

                    foreach (var subName in uninstallKey.GetSubKeyNames())
                    {
                        using var sub = uninstallKey.OpenSubKey(subName);
                        var displayName = sub?.GetValue("DisplayName")?.ToString();
                        if (string.IsNullOrWhiteSpace(displayName)) continue;

                        if ((sub.GetValue("SystemComponent") as int?) == 1) continue;

                        list.Add(new PackageInfo
                        {
                            Type = PackageType.Win32,
                            DisplayName = displayName,
                            Publisher = sub.GetValue("Publisher")?.ToString() ?? "Unknown",
                            Version = sub.GetValue("DisplayVersion")?.ToString() ?? "Unknown",
                            UninstallString = sub.GetValue("UninstallString")?.ToString(),
                            ProductCode = subName
                        });
                    }
                }
                catch { /* ignore bad hives */ }
            }

            return list;
        }

        private static List<PackageInfo> EnumerateUwpPackages()
        {
            var list = new List<PackageInfo>();

            var pm = new PackageManager();
            var packages = pm.FindPackagesForUser(string.Empty); 

            foreach (var pkg in packages)
            {
                try
                {
                    // Skip frameworks/resources (not uninstallable “apps”)
                    if (pkg.IsFramework || pkg.IsResourcePackage) continue;

                    var id = pkg.Id;

                    // DisplayName can be empty -> fallback to package name
                    var name = string.IsNullOrWhiteSpace(pkg.DisplayName) ? id?.Name : pkg.DisplayName;

                    var v = id?.Version;
                    var version = v is null ? "Unknown" : $"{v.Value.Major}.{v.Value.Minor}.{v.Value.Build}.{v.Value.Revision}";

                    list.Add(new PackageInfo
                    {
                        Type = PackageType.Uwp,
                        DisplayName = name ?? "Unknown",
                        Publisher = CleanPublisher(id?.Publisher ?? "Unknown"),  // Provide a default value if id?.Publisher is null
                        Version = version ?? "Unknown",  // Ensure version is not null (add a default if needed)
                        PackageFullName = id?.FullName ?? "Unknown",  // Provide a default if id?.FullName is null
                        PackageFamilyName = id?.FamilyName ?? "Unknown"  // Provide a default if id?.FamilyName is null
                    });

                }
                catch
                {
                }
            }

            return list;
        }

        private static async Task UninstallUwpAsync(PackageInfo p)
        {
            if (string.IsNullOrWhiteSpace(p.PackageFullName))
                throw new InvalidOperationException("Missing PackageFullName for UWP package.");

            var pm = new PackageManager();

            var first = await pm.RemovePackageAsync(p.PackageFullName, RemovalOptions.None)
                                .AsTask().ConfigureAwait(false);

            if (IsSuccess(first)) return;

            const int HR_PACKAGE_IN_USE = unchecked((int)0x80073D02);
            const int HR_ACCESS_DENIED = unchecked((int)0x80070005);
            const int HR_PACKAGE_NOTFOUND = unchecked((int)0x80073CF1);

            var hr = first.ExtendedErrorCode?.HResult ?? unchecked((int)0x80004005); // E_FAIL fallback

            if (hr == HR_PACKAGE_IN_USE)
            {
                System.Windows.Application.Current.Dispatcher.Invoke(() =>
                {
                    System.Windows.MessageBox.Show(
                        $"'{p.DisplayName}' is currently running. Please close it and click OK to retry.",
                        "App In Use", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
                });

                var retry = await pm.RemovePackageAsync(p.PackageFullName, RemovalOptions.None)
                                    .AsTask().ConfigureAwait(false);

                if (IsSuccess(retry)) return;

                throw new InvalidOperationException(BuildError(
                    $"Failed to remove '{p.DisplayName}' after retry.", retry));
            }

            if (hr == HR_ACCESS_DENIED)
            {
                throw new InvalidOperationException(
                    "Access denied. Try running this app as Administrator.");
            }

            if (hr == HR_PACKAGE_NOTFOUND)
            {
                throw new InvalidOperationException(
                    "Package not found for the current user.");
            }

            throw new InvalidOperationException(BuildError(
                $"Failed to remove '{p.DisplayName}'.", first));
        }

        private static bool IsSuccess(DeploymentResult r) =>
            r?.ExtendedErrorCode == null || r.ExtendedErrorCode.HResult == 0;

        private static string BuildError(string prefix, DeploymentResult r)
        {
            var hr = r?.ExtendedErrorCode?.HResult ?? unchecked((int)0x80004005);
            var text = string.IsNullOrWhiteSpace(r?.ErrorText) ? ExplainHr(hr) : r!.ErrorText!.Trim();
            return $"{prefix} 0x{hr:X8}: {text}";
        }

        private static string ExplainHr(int hr) => hr switch
        {
            unchecked((int)0x80073D02) => "The app is in use. Close it and try again.",
            unchecked((int)0x80073CF1) => "Package not found.",
            unchecked((int)0x80073CFA) => "Removal failed. The package may be system-protected or blocked by policy.",
            unchecked((int)0x80073CF6) => "Generic deployment failure.",
            unchecked((int)0x80073D21) => "Operation blocked by policy (system/inbox app).",
            unchecked((int)0x80070005) => "Access denied.",
            _ => "Unknown deployment error."
        };

        private static string CleanPublisher(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return "Unknown";

            // Look for CN= in the publisher string
            var parts = raw.Split(',');
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed.Substring(3).Trim();
            }

            return raw; // fallback to original if CN= not found
        }

        private async Task SearchPackagesAsync(string query)
        {
            if (string.IsNullOrWhiteSpace(query) || _isSearching) return;

            var exactMode = query.StartsWith("!");
            var term = exactMode ? query.Substring(1).Trim() : query.Trim();
            if (string.IsNullOrWhiteSpace(term)) return;

            _isSearching = true;
            _packages.Clear();
            InstallLoadingPanel.Visibility = Visibility.Visible;
            InstallEmptyStatePanel.Visibility = Visibility.Collapsed;
            InstallPackageCountText.Text = exactMode ? "(Exact search...)" : "(Searching...)";

            try
            {
                var args = exactMode
                    ? $"search \"{term}\" -r --exact --page-size=100"
                    : $"search \"{term}\" -r --page-size=100";

                var output = await RunCommandAsync("choco", args);

                var lines = output
                    .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(l => l.Contains("|"))
                    .ToList();

                // Exact mode
                if (exactMode)
                {
                    lines = lines
                        .Select(l => l.Split('|'))
                        .Where(p => p.Length >= 2 && p[0].Equals(term, StringComparison.OrdinalIgnoreCase))
                        .Select(p => string.Join("|", p[0], p[1]))
                        .ToList();
                }
                else
                {
                    if (lines.Count == 0)
                    {
                        var wildcardArgs = $"search \"*{term}*\" -r --page-size=100";
                        var wildcardOutput = await RunCommandAsync("choco", wildcardArgs);
                        lines = wildcardOutput
                            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                            .Where(l => l.Contains("|"))
                            .ToList();
                    }
                }

                foreach (var line in lines)
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 2)
                    {
                        _packages.Add(new PackageItem
                        {
                            Title = parts[0],
                            Version = parts[1],
                            Summary = "",
                            Authors = "",
                            ButtonText = "Select",
                            IsButtonEnabled = true
                        });
                    }
                }

                InstallPackageCountText.Text = _packages.Count == 1
                    ? "1 result"
                    : $"{_packages.Count} results";

                InstallEmptyStatePanel.Visibility = _packages.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error searching packages:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                InstallEmptyStatePanel.Visibility = Visibility.Visible;
            }
            finally
            {
                InstallLoadingPanel.Visibility = Visibility.Collapsed;
                _isSearching = false;
            }
        }



        private async void InstallSelectButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is PackageItem pkg)
            {
                pkg.IsSelected = !pkg.IsSelected;
                pkg.ButtonText = pkg.IsSelected ? "Selected" : "Select";
                if (pkg.IsSelected)
                    _selectedPackages.Add(pkg);
                else
                    _selectedPackages.Remove(pkg);

                UpdateSelectedCount();
            }
        }

        private void UpdateSelectedCount()
        {
            InstallSelectedCountText.Text = $"{_selectedPackages.Count} selected";
            InstallButton.IsEnabled = _selectedPackages.Count > 0;
        }

        private void InstallSelectAllCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            foreach (var pkg in _packages)
            {
                if (!pkg.IsSelected)
                {
                    pkg.IsSelected = true;
                    pkg.ButtonText = "Selected";
                    if (!_selectedPackages.Contains(pkg))
                        _selectedPackages.Add(pkg);
                }
            }
            UpdateSelectedCount();
        }

        private void InstallSelectAllCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            foreach (var pkg in _packages)
            {
                pkg.IsSelected = false;
                pkg.ButtonText = "Select";
            }
            _selectedPackages.Clear();
            UpdateSelectedCount();
        }

        private void InstallClearButton_Click(object sender, RoutedEventArgs e)
        {
            // stop search
            _searchCts?.Cancel();

            InstallSearchTextBox.Text = "";
            ShowDefaultPackages();
            InstallPackageCountText.Text = $"{_packages.Count} recommended packages";
        }


        private async void InstallButton_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedPackages.Count == 0) return;

            var confirm = MessageBox.Show(
                $"Are you sure you want to install {_selectedPackages.Count} package(s)?",
                "Confirm Install",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (confirm != MessageBoxResult.Yes) return;

            var originalText = InstallButton.Content.ToString();
            InstallButton.Content = "Installing...";
            InstallButton.IsEnabled = false;
            InstallButtonBorder.Background = System.Windows.Media.Brushes.Gray;

            foreach (var pkg in _selectedPackages)
            {
                pkg.ButtonText = "Installing...";
                pkg.IsButtonEnabled = false;
                await RunCommandAsync("choco", $"install {pkg.Title} -y");
                pkg.ButtonText = "Installed";
            }

            _selectedPackages.Clear();
            UpdateSelectedCount();

            InstallButton.Content = originalText;
            InstallButton.IsEnabled = true;
            InstallButtonBorder.Background = System.Windows.Media.Brushes.Green;
        }


        private Task<string> RunCommandAsync(string fileName, string arguments)
        {
            return Task.Run(() =>
            {
                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var process = Process.Start(psi))
                {
                    var output = process.StandardOutput.ReadToEnd();
                    var error = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    return output + Environment.NewLine + error;
                }
            });
        }

        

        private async void ToggleHandler(object sender, RoutedEventArgs e)
        {
            if (!(sender is CheckBox cb)) return;
            bool? state = cb.IsChecked;

            if (state == null)
            {
                bmLog.Text = $"No change ({cb.Content})";
                return;
            }

            bmLog.Text = "Please wait...";
            cb.IsEnabled = false;

            try
            {
                switch (cb.Name)
                {
                    case "cbClassicContextMenu":
                        await Task.Run(() => ToggleClassicContextMenu(state == true));
                        bmLog.Text = state == true
                            ? "Classic context menu restored"
                            : "Original context menu restored";
                        break;

                    case "cbPowerThrottling":
                        await Task.Run(() => TogglePowerThrottling(state == true));
                        bmLog.Text = state == true
                            ? "Enabled Power Throttling"
                            : "Disabled Power Throttling";
                        break;

                    case "cbWindowsUpdate":
                        await Task.Run(() => ToggleWindowsUpdate(state == true));
                        bmLog.Text = state == true
                            ? "Windows Update enabled"
                            : "Windows Update disabled";
                        break;

                    case "cbAnimations":
                        await Task.Run(() => ToggleAnimations(state == true));
                        bmLog.Text = state == true ? "Enabled Visual Effects" : "Disabled Visual Effects";
                        break;

                    case "cbDarkTheme":
                        await Task.Run(() => ToggleDarkTheme(state == true));
                        bmLog.Text = state == true ? "Dark theme enabled" : "Light theme enabled";
                        break;

                    case "cbWindowsCopilot":
                        await Task.Run(() => ToggleWindowsCopilot(state == true));
                        bmLog.Text = state == true ? "Windows Copilot enabled" : "Windows Copilot disabled";
                        break;

                    case "cbShowFileExtensions":
                        await Task.Run(() => ToggleShowFileExtensions(state == true));
                        bmLog.Text = state == true ? "File extensions are visible" : "File extensions are hidden";
                        break;

                    case "cbHibernation":
                        await Task.Run(() => ToggleHibernation(state == true));
                        bmLog.Text = state == true ? "Hibernation enabled" : "Hibernation disabled";
                        break;

                    case "cbVerboseLogon":
                        await Task.Run(() => ToggleVerboseLogon(state == true));
                        bmLog.Text = state == true ? "Verbose logon enabled" : "Verbose logon disabled";
                        break;

                    case "cbGameBar":
                        await Task.Run(() => ToggleGameBar(state == true));
                        bmLog.Text = state == true ? "Game Mode enabled" : "Game Mode disabled";
                        break;

                    case "cbExplorerThisPC":
                        await Task.Run(() => ToggleExplorerThisPC(state == true));
                        bmLog.Text = state == true ? "Explorer opens to This PC" : "Explorer opens to Quick Access";
                        break;

                    case "cbWindowsErrorReporting":
                        await Task.Run(() => ToggleWindowsErrorReporting(state == true));
                        bmLog.Text = state == true ? "Windows Error Reporting enabled" : "Windows Error Reporting disabled";
                        break;


                    default:
                        bmLog.Text = $"No action defined for {cb.Name}";
                        break;
                }
            }
            catch (Exception ex)
            {
                bmLog.Text = "Error: " + ex.Message;
            }
            finally
            {
                cb.IsEnabled = true;
            }
        }

        // === INDIVIDUAL ACTIONS ===

        private void ToggleClassicContextMenu(bool enable)
        {
            string keyPath = @"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}";

            if (enable)
            {
                using (var clsid = Registry.CurrentUser.CreateSubKey(keyPath))
                using (var inproc = Registry.CurrentUser.CreateSubKey(keyPath + @"\InprocServer32"))
                {
                    inproc.SetValue("", "", RegistryValueKind.String);
                }
            }
            else
            {
                using (var parent = Registry.CurrentUser.OpenSubKey(@"Software\Classes\CLSID", writable: true))
                {
                    parent?.DeleteSubKeyTree("{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}", throwOnMissingSubKey: false);
                }
            }

            RestartExplorer();
        }

        private void TogglePowerThrottling(bool enable)
        {
            int value = enable ? 0 : 1;
            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling",
                "PowerThrottlingOff",
                value,
                RegistryValueKind.DWord);

            RunCommand("powercfg.exe", "-setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
        }

        private void ToggleWindowsUpdate(bool enable)
        {
            if (enable)
            {
                RunCommand("sc.exe", "config wuauserv start=auto");
                RunCommand("sc.exe", "start wuauserv");
            }
            else
            {
                RunCommand("sc.exe", "config wuauserv start=disabled");
                RunCommand("sc.exe", "stop wuauserv");
            }
        }

        private void ToggleAnimations(bool enable)
        {
            if (enable)
            {
                Registry.SetValue(@"HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics", "MinAnimate", "1", RegistryValueKind.String);

                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ListviewAlphaSelect", 1, RegistryValueKind.DWord);
                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ListviewShadow", 1, RegistryValueKind.DWord);
                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarAnimations", 1, RegistryValueKind.DWord);

                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting", 1, RegistryValueKind.DWord);

                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM", "EnableAeroPeek", 0, RegistryValueKind.DWord);
            }
            else
            {
                Registry.SetValue(@"HKEY_CURRENT_USER\Control Panel\Desktop", "MenuShowDelay", "200", RegistryValueKind.String);

                // Set UserPreferencesMask as binary 144, 18, 3, 128, 16, 0, 0, 0
                byte[] mask = new byte[] { 144, 18, 3, 128, 16, 0, 0, 0 };
                Registry.SetValue(@"HKEY_CURRENT_USER\Control Panel\Desktop", "UserPreferencesMask", mask, RegistryValueKind.Binary);

                Registry.SetValue(@"HKEY_CURRENT_USER\Control Panel\Desktop", "MinAnimate", "0", RegistryValueKind.String);

                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ListviewAlphaSelect", 0, RegistryValueKind.DWord);
                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ListviewShadow", 0, RegistryValueKind.DWord);
                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarAnimations", 0, RegistryValueKind.DWord);

                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting", 3, RegistryValueKind.DWord);

                Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM", "EnableAeroPeek", 0, RegistryValueKind.DWord);
            }
            RestartExplorer();
        }


        // ===== Dark Theme (Apps + System) =====
        private void ToggleDarkTheme(bool enable)
        {
            int v = enable ? 0 : 1; // 0 = Dark, 1 = Light
            string personalize = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
            Registry.SetValue(personalize, "AppsUseLightTheme", v, RegistryValueKind.DWord);
            Registry.SetValue(personalize, "SystemUsesLightTheme", v, RegistryValueKind.DWord);
        }

        // ===== Windows Copilot (policy + taskbar button) =====
        private void ToggleWindowsCopilot(bool enable)
        {
            try
            {
                // Policy: 1 = Turn off (disable), 0 = allow
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
                                  "TurnOffWindowsCopilot", enable ? 0 : 1, RegistryValueKind.DWord);
            }
            catch {}

            // Taskbar button (doesn’t fully disable feature, just the button)
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                              "ShowCopilotButton", enable ? 1 : 0, RegistryValueKind.DWord);

            RestartExplorer(); // reflect taskbar changes
        }

        // ===== Show File Extensions =====
        private void ToggleShowFileExtensions(bool show)
        {
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                              "HideFileExt", show ? 0 : 1, RegistryValueKind.DWord);
            RestartExplorer();
        }

        // ===== Hibernation =====
        private void ToggleHibernation(bool enable)
        {
            RunCommand("powercfg.exe", enable ? "/hibernate on" : "/hibernate off");
        }

        // ===== Verbose Logon =====
        private void ToggleVerboseLogon(bool enable)
        {
            try
            {
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                                  "VerboseStatus", enable ? 1 : 0, RegistryValueKind.DWord);
            }
            catch {}
        }

        // ===== Game Mode =====
        private void ToggleGameBar(bool enable)
        {
            // Core flags commonly toggled
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR",
                              "AppCaptureEnabled", enable ? 1 : 0, RegistryValueKind.DWord);

            Registry.SetValue(@"HKEY_CURRENT_USER\System\GameConfigStore",
                              "GameDVR_Enabled", enable ? 1 : 0, RegistryValueKind.DWord);

            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\GameBar",
                              "ShowStartupPanel", enable ? 1 : 0, RegistryValueKind.DWord);

            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\GameBar",
                              "AutoGameModeEnabled", enable ? 1 : 0, RegistryValueKind.DWord);
        }

        // ===== File Explorer opens to "This PC" (true) or Quick Access (false) =====
        private void ToggleExplorerThisPC(bool thisPc)
        {
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                              "LaunchTo", thisPc ? 1 : 2, RegistryValueKind.DWord);
            RestartExplorer();
        }

        // ===== Windows Error Reporting (WER) =====
        private void ToggleWindowsErrorReporting(bool enable)
        {
            try
            {
                // HKLM policy: Disabled = 1 (turn off WER), 0 or missing = enabled
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting",
                                  "Disabled", enable ? 0 : 1, RegistryValueKind.DWord);
            }
            catch {}
        }

        // === HELPER METHODS ===

        private void RestartExplorer()
        {
            RunCommand("taskkill", "/f /im explorer.exe");
            System.Threading.Thread.Sleep(500);
            RunCommand("explorer.exe", "");
        }

        private void RunCommand(string fileName, string arguments)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false
            };

            using (var process = Process.Start(psi))
            {
                process?.WaitForExit();
            }
        }
    }
}