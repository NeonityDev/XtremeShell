using Microsoft.Win32;
using Windows.Management.Deployment;

namespace XtremeShell.Services
{
    public static class AppUninstallService
    {
        public static List<PackageInfo> EnumerateWin32FromRegistry()
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
                    if (uninstallKey == null)
                        continue;

                    foreach (var subName in uninstallKey.GetSubKeyNames())
                    {
                        using var sub = uninstallKey.OpenSubKey(subName);
                        var displayName = sub?.GetValue("DisplayName")?.ToString();
                        if (string.IsNullOrWhiteSpace(displayName))
                            continue;
                        if (sub == null)
                            continue;

                        if ((sub.GetValue("SystemComponent") as int?) == 1)
                            continue;

                        list.Add(new PackageInfo
                        {
                            Type = PackageType.Win32,
                            DisplayName = displayName,
                            Publisher = sub.GetValue("Publisher")?.ToString() ?? "Unknown",
                            Version = sub.GetValue("DisplayVersion")?.ToString() ?? "Unknown",
                            UninstallString = sub.GetValue("UninstallString")?.ToString() ?? string.Empty,
                            ProductCode = subName
                        });
                    }
                }
                catch
                {
                }
            }

            return list;
        }

        public static List<PackageInfo> EnumerateUwpPackages()
        {
            var list = new List<PackageInfo>();
            var packageManager = new PackageManager();
            var packages = packageManager.FindPackagesForUser(string.Empty);

            foreach (var package in packages)
            {
                try
                {
                    if (package.IsFramework || package.IsResourcePackage)
                        continue;

                    var id = package.Id;
                    var name = string.IsNullOrWhiteSpace(package.DisplayName)
                        ? id?.Name
                        : package.DisplayName;

                    var versionInfo = id?.Version;
                    var version = versionInfo is null
                        ? "Unknown"
                        : $"{versionInfo.Value.Major}.{versionInfo.Value.Minor}.{versionInfo.Value.Build}.{versionInfo.Value.Revision}";

                    list.Add(new PackageInfo
                    {
                        Type = PackageType.Uwp,
                        DisplayName = name ?? "Unknown",
                        Publisher = CleanPublisher(id?.Publisher ?? "Unknown"),
                        Version = version,
                        PackageFullName = id?.FullName ?? "Unknown",
                        PackageFamilyName = id?.FamilyName ?? "Unknown"
                    });
                }
                catch
                {
                }
            }

            return list;
        }

        public static void UninstallWin32(PackageInfo package)
        {
            if (string.IsNullOrWhiteSpace(package.UninstallString))
                return;

            var uninstallCommand = package.UninstallString.Trim();

            if (uninstallCommand.StartsWith("MsiExec.exe", StringComparison.OrdinalIgnoreCase) ||
                uninstallCommand.StartsWith("msiexec", StringComparison.OrdinalIgnoreCase))
            {
                var arguments = uninstallCommand
                    .Replace("MsiExec.exe", "", StringComparison.OrdinalIgnoreCase)
                    .Replace("msiexec", "", StringComparison.OrdinalIgnoreCase)
                    .Trim();

                if (arguments.Contains("/I ", StringComparison.OrdinalIgnoreCase))
                    arguments = arguments.Replace("/I", "/X", StringComparison.OrdinalIgnoreCase);
                else if (!arguments.Contains("/X", StringComparison.OrdinalIgnoreCase))
                    arguments = "/X " + arguments;

                arguments += " /quiet /norestart";

                CommandRunner.Run("msiexec.exe", arguments, timeoutMilliseconds: 30000);
                return;
            }

            ParseExeAndRun(uninstallCommand, " /S /silent");
        }

        public static async Task UninstallUwpAsync(
            PackageInfo package,
            Func<PackageInfo, Task>? onPackageInUse = null)
        {
            if (string.IsNullOrWhiteSpace(package.PackageFullName))
                throw new InvalidOperationException("Missing PackageFullName for UWP package.");

            var packageManager = new PackageManager();

            var first = await packageManager.RemovePackageAsync(package.PackageFullName, RemovalOptions.None)
                .AsTask()
                .ConfigureAwait(false);

            if (IsSuccess(first))
                return;

            const int hrPackageInUse = unchecked((int)0x80073D02);
            const int hrAccessDenied = unchecked((int)0x80070005);
            const int hrPackageNotFound = unchecked((int)0x80073CF1);

            var hr = first.ExtendedErrorCode?.HResult ?? unchecked((int)0x80004005);

            if (hr == hrPackageInUse)
            {
                if (onPackageInUse != null)
                    await onPackageInUse(package).ConfigureAwait(false);

                var retry = await packageManager.RemovePackageAsync(package.PackageFullName, RemovalOptions.None)
                    .AsTask()
                    .ConfigureAwait(false);

                if (IsSuccess(retry))
                    return;

                throw new InvalidOperationException(BuildError(
                    $"Failed to remove '{package.DisplayName}' after retry.", retry));
            }

            if (hr == hrAccessDenied)
                throw new InvalidOperationException("Access denied. Try running this app as Administrator.");

            if (hr == hrPackageNotFound)
                throw new InvalidOperationException("Package not found for the current user.");

            throw new InvalidOperationException(BuildError(
                $"Failed to remove '{package.DisplayName}'.", first));
        }

        private static void ParseExeAndRun(string command, string extraArguments)
        {
            string fileName;
            var arguments = "";
            var trimmedCommand = command.Trim();

            if (trimmedCommand.StartsWith("\""))
            {
                var end = trimmedCommand.IndexOf("\"", 1);
                fileName = end > 0 ? trimmedCommand.Substring(1, end - 1) : trimmedCommand.Trim('"');
                if (end > 0 && trimmedCommand.Length > end + 1)
                    arguments = trimmedCommand[(end + 1)..].Trim();
            }
            else
            {
                var exeIndex = trimmedCommand.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                if (exeIndex > 0)
                {
                    fileName = trimmedCommand.Substring(0, exeIndex + 4);
                    if (trimmedCommand.Length > exeIndex + 4)
                        arguments = trimmedCommand[(exeIndex + 4)..].Trim();
                }
                else
                {
                    fileName = trimmedCommand;
                }
            }

            if (!string.IsNullOrEmpty(extraArguments))
                arguments = (arguments + " " + extraArguments).Trim();

            CommandRunner.Run(fileName, arguments, timeoutMilliseconds: 30000);
        }

        private static bool IsSuccess(DeploymentResult result) =>
            result?.ExtendedErrorCode == null || result.ExtendedErrorCode.HResult == 0;

        private static string BuildError(string prefix, DeploymentResult result)
        {
            var hr = result?.ExtendedErrorCode?.HResult ?? unchecked((int)0x80004005);
            var text = string.IsNullOrWhiteSpace(result?.ErrorText)
                ? ExplainHr(hr)
                : result!.ErrorText!.Trim();

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

            var parts = raw.Split(',');
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed.Substring(3).Trim();
            }

            return raw;
        }
    }
}
