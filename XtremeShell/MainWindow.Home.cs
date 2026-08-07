using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using IOPath = System.IO.Path;

namespace XtremeShell
{
    public partial class MainWindow
    {
        private void xsVersion_Click(object sender, RoutedEventArgs e)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "https://xtremeshell.neonity.hu",
                UseShellExecute = true
            });
        }

        private void DebloatBrave_Click(object sender, RoutedEventArgs e)
        {
            BraveDebloatWindow window = _isPresetBuilderActive
                ? new BraveDebloatWindow(true, RecordBravePresetEntries)
                : new BraveDebloatWindow();

            window.Owner = this;
            window.ShowDialog();
        }

        private void RecordBravePresetEntries(IReadOnlyList<PresetEntry> entries)
        {
            foreach (PresetEntry entry in entries)
            {
                UpsertPresetEntry(entry);
            }

            bmLog.Text = entries.Count + " Brave debloat option(s) added to preset.";
        }

        private async void button_Click(object sender, RoutedEventArgs e)
        {
            bmLog.Text = ("");
            var clickedButton = sender as Button;
            if (clickedButton == null)
                return;

            if (_isPresetBuilderActive && IsPresetRecordableButton(clickedButton.Name))
            {
                RecordHomeAction(clickedButton);
                return;
            }

            switch (clickedButton.Name)
            {
                case "bmExit":
                    if (_exitRequested)
                    {
                        this.Close();
                        break;
                    }

                    _exitRequested = true;
                    bmLog.Text = "Thanks for using XtremeShell!";

                    _ = Task.Run(async () =>
                    {
                        await Task.Delay(500);
                        Dispatcher.Invoke(() =>
                        {
                            if (_exitRequested) this.Close();
                        });
                    });
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
                    ? ""
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

    }
}
