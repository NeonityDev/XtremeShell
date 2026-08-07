using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using XtremeShell.Services;

namespace XtremeShell
{
    public partial class MainWindow
    {
        /// <summary>
        /// Package Store
        /// </summary>
        /// 

        private readonly List<(string Category, string Name, string Id)> _defaultPackages = new()
{
    ("Browsers", "Brave", "brave"),
    ("Browsers", "Helium", "helium"),
    ("Browsers", "Mozilla Firefox", "firefox"),
    ("Browsers", "Google Chrome", "googlechrome"),

    ("Gaming", "Steam", "steam"),
    ("Gaming", "Epic Games Launcher", "epicgameslauncher"),
    ("Gaming", "GOG Galaxy", "goggalaxy"),
    ("Gaming", "OBS Studio", "obs-studio"),

    ("Creator", "Audacity", "audacity"),
    ("Creator", "Blender", "blender"),
    ("Creator", "HandBrake", "handbrake"),
    ("Creator", "GIMP", "gimp"),

    ("Development", "VSCodium", "vscodium"),
    ("Development", "Git", "git"),
    ("Development", "Node.js LTS", "nodejs-lts"),
    ("Development", "Python", "python"),

    ("Media", "VLC media player", "vlc"),
    ("Media", "MPC-HC", "mpc-hc"),
    ("Media", "Spotify", "spotify"),
    ("Media", "Jellyfin Media Player", "jellyfin-media-player"),

    ("File Management", "7-Zip", "7zip"),
    ("File Management", "WinRAR", "winrar"),
    ("File Management", "WizTree", "wiztree"),
    ("File Management", "Everything", "everything"),

    ("Network", "MobaXterm", "mobaxterm"),
    ("Network", "Wireshark", "wireshark"),
    ("Network", "PuTTY", "putty"),
    ("Network", "WinSCP", "winscp"),

    ("Communication", "Discord", "discord"),
    ("Communication", "Telegram Desktop", "telegram"),
    ("Communication", "Signal", "signal"),
    ("Communication", "Slack", "slack"),

    ("Hardware Tools", "HWiNFO", "hwinfo"),
    ("Hardware Tools", "CPU-Z", "cpu-z"),
    ("Hardware Tools", "GPU-Z", "gpu-z"),
    ("Hardware Tools", "CrystalDiskInfo", "crystaldiskinfo")
};


        private void ShowDefaultPackages()
        {
            _packages.Clear();
            _selectedPackages.Clear();
            _packageCategories.Clear();
            _installQueue.Clear();
            _installQueueByTitle.Clear();

            foreach (var group in _defaultPackages.GroupBy(p => p.Category))
            {
                var category = new PackageCategory { Name = group.Key };

                foreach (var p in group)
                {
                    var package = new PackageItem
                    {
                        Title = p.Id,
                        Summary = p.Name,
                        Category = p.Category,
                        IsSelected = false
                    };

                    _packages.Add(package);
                    category.Packages.Add(package);
                }

                _packageCategories.Add(category);
            }

            InstallPackageCountText.Text = $"{_packages.Count} recommended apps";
            InstallEmptyStatePanel.Visibility = _packages.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            InstallLoadingPanel.Visibility = Visibility.Collapsed;
            UpdateSelectedCount();
            _ = EnrichPackageCardsAsync(_packages.ToList());
        }


        private CancellationTokenSource? _searchCts;

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


        private async Task SearchPackagesAsync(string query)
        {
            if (string.IsNullOrWhiteSpace(query) || _isSearching) return;

            var exactMode = query.StartsWith("!");
            var term = exactMode ? query.Substring(1).Trim() : query.Trim();
            if (string.IsNullOrWhiteSpace(term)) return;

            _isSearching = true;
            _packages.Clear();
            _packageCategories.Clear();
            InstallLoadingPanel.Visibility = Visibility.Visible;
            InstallEmptyStatePanel.Visibility = Visibility.Collapsed;
            InstallPackageCountText.Text = exactMode ? "(Exact search...)" : "(Searching...)";

            try
            {
                var args = exactMode
                    ? $"search \"{term}\" -r --exact --page-size=96"
                    : $"search \"{term}\" -r --page-size=48";

                var output = await CommandRunner.RunAsync("choco", args);

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
                        var wildcardOutput = await CommandRunner.RunAsync("choco", wildcardArgs);
                        lines = wildcardOutput
                            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                            .Where(l => l.Contains("|"))
                            .ToList();
                    }
                }

                var searchCategory = new PackageCategory { Name = "Search results" };

                foreach (var line in lines)
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 2)
                    {
                        var package = new PackageItem
                        {
                            Title = parts[0],
                            Version = parts[1],
                            Summary = parts[0],
                            Category = "Search results",
                            IsSelected = _selectedPackages.Any(selected =>
                                selected.Title.Equals(parts[0], StringComparison.OrdinalIgnoreCase))
                        };

                        _packages.Add(package);
                        searchCategory.Packages.Add(package);
                    }
                }

                if (searchCategory.Packages.Count > 0)
                    _packageCategories.Add(searchCategory);

                InstallPackageCountText.Text = _packages.Count == 1
                    ? "1 result"
                    : $"{_packages.Count} results";
                if(_packages.Count == 48)  InstallPackageCountText.Text = $"{_packages.Count} results (max)";

                InstallEmptyStatePanel.Visibility = _packages.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
                _ = EnrichPackageCardsAsync(_packages.ToList());
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

        private async Task EnrichPackageCardsAsync(List<PackageItem> packageItems)
        {
            if (packageItems.Count == 0)
                return;

            await EnsurePackageStateCacheAsync();

            foreach (var package in packageItems)
            {
                package.IsInstalled = _installedPackageIds.Contains(package.Title);
                package.IsUpdateAvailable = _outdatedPackageIds.Contains(package.Title);

                var cachedIcon = PackageIconService.FindCachedPackageIcon(package.Title);
                if (!string.IsNullOrWhiteSpace(cachedIcon))
                    package.IconPath = cachedIcon;
            }

            foreach (var package in packageItems.Where(p => string.IsNullOrWhiteSpace(p.IconPath)))
            {
                await PackageIconService.LoadPackageIconAsync(package);
            }
        }

        private async Task EnsurePackageStateCacheAsync()
        {
            if (_packageStateCacheLoaded)
                return;

            _packageStateCacheLoaded = true;

            try
            {
                var installedOutput = await CommandRunner.RunAsync("choco", "list --local-only -r");
                foreach (var line in installedOutput.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('|');
                    if (parts.Length > 0 && !string.IsNullOrWhiteSpace(parts[0]))
                        _installedPackageIds.Add(parts[0].Trim());
                }
            }
            catch
            {
            }

            try
            {
                var outdatedOutput = await CommandRunner.RunAsync("choco", "outdated -r");
                foreach (var line in outdatedOutput.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('|');
                    if (parts.Length > 0 && !string.IsNullOrWhiteSpace(parts[0]))
                        _outdatedPackageIds.Add(parts[0].Trim());
                }
            }
            catch
            {
            }
        }

        private void InstallPackageItem_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is Border border && border.DataContext is PackageItem pkg)
            {
                TogglePackageSelection(pkg);
                e.Handled = true;
            }
        }

        private void TogglePackageSelection(PackageItem pkg)
        {
            if (pkg == null) return;

            ApplyPackageSelection(pkg, !pkg.IsSelected);
            UpdateSelectedCount();
        }

        private void ApplyPackageSelection(PackageItem pkg, bool isSelected)
        {
            if (pkg == null || pkg.IsSelected == isSelected)
                return;

            foreach (var visiblePackage in _packages.Where(p =>
                         p.Title.Equals(pkg.Title, StringComparison.OrdinalIgnoreCase)))
            {
                visiblePackage.IsSelected = isSelected;
            }

            if (isSelected)
            {
                if (!_selectedPackages.Any(selected =>
                        selected.Title.Equals(pkg.Title, StringComparison.OrdinalIgnoreCase)))
                    _selectedPackages.Add(pkg);

                UpsertInstallQueueItem(pkg, "Pending");
            }
            else
            {
                foreach (var selected in _selectedPackages
                             .Where(selected => selected.Title.Equals(pkg.Title, StringComparison.OrdinalIgnoreCase))
                             .ToList())
                {
                    _selectedPackages.Remove(selected);
                }

                if (_installQueueByTitle.TryGetValue(pkg.Title, out var queueItem) &&
                    queueItem.Status == "Pending")
                {
                    _installQueue.Remove(queueItem);
                    _installQueueByTitle.Remove(pkg.Title);
                }
            }
        }

        private void UpdateSelectedCount()
        {
            InstallSelectedCountText.Text = $"{_selectedPackages.Count} selected";
            InstallButton.IsEnabled = _selectedPackages.Count > 0;
            InstallQueuePanel.Visibility = _installQueue.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private InstallQueueItem UpsertInstallQueueItem(PackageItem package, string status)
        {
            if (!_installQueueByTitle.TryGetValue(package.Title, out var queueItem))
            {
                queueItem = new InstallQueueItem
                {
                    Title = package.Title,
                    Summary = package.Summary
                };

                _installQueueByTitle[package.Title] = queueItem;
                _installQueue.Add(queueItem);
            }

            queueItem.Status = status;
            return queueItem;
        }

        private void InstallSelectAllCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            foreach (var pkg in _packages)
            {
                ApplyPackageSelection(pkg, true);
            }
            UpdateSelectedCount();
        }

        private void InstallSelectAllCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            foreach (var pkg in _packages)
            {
                ApplyPackageSelection(pkg, false);
            }
            UpdateSelectedCount();
        }

        private void InstallClearButton_Click(object sender, RoutedEventArgs e)
        {
            // stop search
            _searchCts?.Cancel();

            InstallSearchTextBox.Text = "";
            ShowDefaultPackages();
            InstallPackageCountText.Text = $"{_packages.Count} recommended apps";
        }


        private async void InstallButton_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedPackages.Count == 0) return;

            if (_isPresetBuilderActive)
            {
                RecordInstallPackagePresetEntries(_selectedPackages.ToList());
                return;
            }

            var confirm = MessageBox.Show(
                $"Are you sure you want to install {_selectedPackages.Count} package(s)?",
                "Confirm Install",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (confirm != MessageBoxResult.Yes) return;

            var originalText = InstallButton.Content.ToString();
            InstallButton.Content = "Installing...";
            InstallButton.IsEnabled = false;
            InstallButtonBorder.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#5A3E4A"));

            var packagesToInstall = new List<PackageItem>(_selectedPackages);

            foreach (var pkg in packagesToInstall)
            {
                var queueItem = UpsertInstallQueueItem(pkg, "Pending");

                if (pkg.IsInstalled && !pkg.IsUpdateAvailable)
                {
                    queueItem.Status = "Skipped";
                    ApplyPackageSelection(pkg, false);
                    continue;
                }

                queueItem.Status = "Downloading";
                await Task.Delay(250);
                queueItem.Status = "Installing";

                var command = pkg.IsUpdateAvailable
                    ? $"upgrade {pkg.Title} -y"
                    : $"install {pkg.Title} -y";

                var result = await CommandRunner.RunWithExitCodeAsync("choco", command);
                var installSucceeded = result.ExitCode == 0 || result.ExitCode == 3010;
                queueItem.Status = installSucceeded ? "Installed" : "Failed";

                if (installSucceeded)
                {
                    pkg.IsInstalled = true;
                    pkg.IsUpdateAvailable = false;
                    _installedPackageIds.Add(pkg.Title);
                    _outdatedPackageIds.Remove(pkg.Title);
                }

                ApplyPackageSelection(pkg, false);
            }

            UpdateSelectedCount();

            InstallButton.Content = originalText;
            InstallButton.IsEnabled = _selectedPackages.Count > 0;
            InstallButtonBorder.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2D6B2D"));
        }


    }
}
