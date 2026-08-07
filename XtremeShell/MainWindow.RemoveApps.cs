using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using XtremeShell.Services;

namespace XtremeShell
{
    public partial class MainWindow
    {
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
                    installedPrograms.AddRange(AppUninstallService.EnumerateWin32FromRegistry());

                    // UWP / Store apps (current user)
                    installedPrograms.AddRange(AppUninstallService.EnumerateUwpPackages());

                    // de-dupe by DisplayName + Version
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

            Dispatcher.Invoke(() =>
            {
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

            if (_isPresetBuilderActive)
            {
                RecordRemoveAppPresetEntries(selectedPackages);
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
            RemoveButton.Content = "Removing...";

            try
            {
                foreach (var package in selectedPackages)
                {
                    try
                    {
                        if (package.Type == PackageType.Uwp &&
                            !string.IsNullOrWhiteSpace(package.PackageFullName))
                        {
                            await AppUninstallService.UninstallUwpAsync(package, PromptPackageInUseRetryAsync);
                        }
                        else if (!string.IsNullOrEmpty(package.UninstallString))
                        {
                            await Task.Run(() => AppUninstallService.UninstallWin32(package));
                        }
                        else
                        {
                            MessageBox.Show($"No uninstall method for {package.DisplayName}.",
                                "Uninstall", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed to uninstall {package.DisplayName}: {ex.Message}",
                            "Uninstall Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
                LoadPackagesAsync();
            }
            finally
            {
                RemoveButton.Content = originalText;
                RemoveButton.IsEnabled = true;
            }
        }

        private Task PromptPackageInUseRetryAsync(PackageInfo package)
        {
            return Dispatcher.InvokeAsync(() =>
            {
                MessageBox.Show(
                    $"'{package.DisplayName}' is currently running. Please close it and click OK to retry.",
                    "App In Use",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }).Task;
        }


    }
}
