using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace XtremeShell5
{
    public partial class MainWindow
    {
        // Chocolatey check on startup
        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            bool hasChoco = await Task.Run(IsChocolateyInstalled);

            if (hasChoco)
                return;

            var result = MessageBox.Show(
                "Chocolatey is not installed. Do you want to install it now?",
                "Chocolatey",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                bmLog.Text = "Installing Chocolatey...";
                bool installed = await InstallChocolateyAsync();

                if (!installed)
                {
                    MessageBox.Show(
                        "Chocolatey installation was cancelled or failed.",
                        "Chocolatey",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);

                    HidePackageStoreTab();
                }
            }
            else
            {
                bmLog.Text = "WARNING: Chocolatey is not installed. Package Store is unavailable.";
                HidePackageStoreTab();
            }
        }

        private void HidePackageStoreTab()
        {
            if (PackageStoreTab != null)
            {
                PackageStoreTab.Visibility = Visibility.Collapsed;
                return;
            }

            var tab = RootTabs?.Items
                .OfType<System.Windows.Controls.TabItem>()
                .FirstOrDefault(t => (t.Header as string)?.Equals("Package Store", StringComparison.OrdinalIgnoreCase) == true);

            if (tab != null)
                tab.Visibility = Visibility.Collapsed;
        }

        private static bool IsChocolateyInstalled()
        {
            try
            {
                var env = Environment.GetEnvironmentVariable("ChocolateyInstall", EnvironmentVariableTarget.Machine)
                          ?? Environment.GetEnvironmentVariable("ChocolateyInstall", EnvironmentVariableTarget.User)
                          ?? Environment.GetEnvironmentVariable("ChocolateyInstall", EnvironmentVariableTarget.Process);

                if (!string.IsNullOrWhiteSpace(env))
                {
                    var exe = System.IO.Path.Combine(env, "bin", "choco.exe");
                    if (System.IO.File.Exists(exe)) return true;
                }

                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var fallback = System.IO.Path.Combine(programData, "chocolatey", "bin", "choco.exe");
                if (System.IO.File.Exists(fallback)) return true;

                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c choco -v",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var p = Process.Start(psi);
                if (!p.WaitForExit(3000))
                {
                    try { p.Kill(); } catch { }
                    return false;
                }

                return p.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        private static async Task<bool> InstallChocolateyAsync()
        {
            const string installCmd =
                "Set-ExecutionPolicy Bypass -Scope Process -Force; " +
                "[System.Net.ServicePointManager]::SecurityProtocol = " +
                "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; " +
                "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))";

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{installCmd}\"",
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Normal
            };

            return await Task.Run(() =>
            {
                try
                {
                    using var p = Process.Start(psi);
                    p.WaitForExit();
                    return p.ExitCode == 0;
                }
                catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
                {
                    return false;
                }
                catch
                {
                    return false;
                }
            });
        }

        private async Task<int> RunPowerShellAsync(string psScript, Action<string> onOut, Action<string> onErr)
        {
            var bytes = System.Text.Encoding.Unicode.GetBytes(psScript);
            var encoded = Convert.ToBase64String(bytes);

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
            p.OutputDataReceived += (_, e) => { if (e.Data != null) onOut?.Invoke(e.Data); };
            p.ErrorDataReceived += (_, e) => { if (e.Data != null) onErr?.Invoke(e.Data); };

            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            await Task.Run(() => p.WaitForExit());
            return p.ExitCode;
        }

        private Task SetStatusAsync(string text) =>
            Dispatcher.InvokeAsync(() => bmLog.Text = text).Task;

        private Task AppendLogAsync(string line) =>
            Dispatcher.InvokeAsync(() => bmLog.Text += "\n" + line).Task;

        private async Task InstallOrUpgradeChocolateyAsync()
        {
            try
            {
                await SetStatusAsync("Please wait...");

                var ps = @"
Set-ExecutionPolicy Bypass -Scope Process -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
$ProgressPreference = 'SilentlyContinue'
iwr https://community.chocolatey.org/install.ps1 -UseBasicParsing | iex
choco upgrade chocolatey -y --no-progress
";

                int code = await RunPowerShellAsync(
                    ps,
                    onOut: async s => await AppendLogAsync(s),
                    onErr: async s => await AppendLogAsync(s));

                await SetStatusAsync(code == 0
                    ? "Chocolatey installed/upgraded successfully."
                    : $"Chocolatey install/upgrade failed (exit {code}).");
            }
            catch (Exception ex)
            {
                await SetStatusAsync("Error: " + ex.Message);
            }
        }
    }
}
