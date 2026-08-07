using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;

namespace XtremeShell
{
    public partial class MainWindow
    {
        private async void ToggleHandler(object sender, RoutedEventArgs e)
        {
            if (_isLoadingToggleStates)
            {
                return;
            }

            if (!(sender is CheckBox cb)) return;
            bool? state = cb.IsChecked;

            if (state == null)
            {
                bmLog.Text = $"No change ({cb.Content})";
                return;
            }

            if (_isPresetBuilderActive)
            {
                RecordTogglePresetEntry(cb, state == true);
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
            catch { }

            // Taskbar button
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
            catch { }
        }

        // ===== Game Mode =====
        private void ToggleGameBar(bool enable)
        {
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

        private void ToggleWindowsErrorReporting(bool enable)
        {
            try
            {
                // HKLM policy: Disabled = 1 (turn off WER), 0 or missing = enabled
                Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting",
                                  "Disabled", enable ? 0 : 1, RegistryValueKind.DWord);
            }
            catch { }
        }
    }
}
