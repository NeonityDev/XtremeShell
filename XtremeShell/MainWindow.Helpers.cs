using Microsoft.Win32;
using System.Diagnostics;
using System.Windows.Input;
using XtremeShell.Services;

namespace XtremeShell
{
    public partial class MainWindow
    {
        private void xsBanner_Click(object sender, MouseButtonEventArgs e)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "https://xtremeshell.neonity.hu",
                UseShellExecute = true
            });
        }

        private void RestartExplorer()
        {
            RunCommand("taskkill", "/f /im explorer.exe");
            System.Threading.Thread.Sleep(500);
            RunCommand("explorer.exe", "");
        }

        private void RunCommand(string fileName, string arguments)
        {
            CommandRunner.Run(fileName, arguments);
        }

        private static int? ReadDword(string keyName, string valueName)
        {
            object? value = Registry.GetValue(keyName, valueName, null);
            if (value == null) return null;

            try
            {
                return Convert.ToInt32(value);
            }
            catch
            {
                return null;
            }
        }

        private static string? ReadString(string keyName, string valueName)
        {
            return Registry.GetValue(keyName, valueName, null)?.ToString();
        }

        private static bool IsClassicContextMenuEnabled()
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32");
            return key != null;
        }

        private static bool IsPowerThrottlingEnabled()
        {
            int? off = ReadDword(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling", "PowerThrottlingOff");
            return off != 1;
        }

        private static bool IsWindowsUpdateEnabled()
        {
            int? start = ReadDword(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv", "Start");
            return start != 4;
        }

        private static bool IsAnimationsEnabled()
        {
            string? minAnimate = ReadString(@"HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics", "MinAnimate");
            return minAnimate != "0";
        }

        private static bool IsDarkThemeEnabled()
        {
            int? appsUseLightTheme = ReadDword(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme");
            int? systemUsesLightTheme = ReadDword(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "SystemUsesLightTheme");
            return appsUseLightTheme == 0 && systemUsesLightTheme == 0;
        }

        private static bool IsWindowsCopilotEnabled()
        {
            int? policy = ReadDword(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot");
            int? button = ReadDword(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCopilotButton");
            return policy != 1 && button != 0;
        }

        private static bool IsShowFileExtensionsEnabled()
        {
            int? hideFileExt = ReadDword(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt");
            return hideFileExt == 0;
        }

        private static bool IsHibernationEnabled()
        {
            int? hibernateEnabled = ReadDword(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled");
            return hibernateEnabled == 1;
        }

        private static bool IsVerboseLogonEnabled()
        {
            int? verboseStatus = ReadDword(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "VerboseStatus");
            return verboseStatus == 1;
        }

        private static bool IsGameBarEnabled()
        {
            int? appCapture = ReadDword(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled");
            int? gameDvr = ReadDword(@"HKEY_CURRENT_USER\System\GameConfigStore", "GameDVR_Enabled");
            return appCapture != 0 && gameDvr != 0;
        }

        private static bool IsExplorerThisPCEnabled()
        {
            int? launchTo = ReadDword(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "LaunchTo");
            return launchTo == 1;
        }

        private static bool IsWindowsErrorReportingEnabled()
        {
            int? disabled = ReadDword(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled");
            return disabled != 1;
        }

    }
}
