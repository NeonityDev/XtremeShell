using Microsoft.Win32;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using XtremeShell.Services;

namespace XtremeShell
{
    public partial class MainWindow
    {
        // === PRESETS ===

        private string CurrentXtremeShellVersion => xsVersion.Content?.ToString() ?? string.Empty;

        private void CreatePresetButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_isPresetBuilderActive)
            {
                _presetEntries.Clear();
                SetPresetBuilderActive(true);
                bmLog.Text = "Preset Builder is active. Changes will be recorded, not applied.";
                return;
            }

            SaveCurrentPreset();
        }

        private void ImportPresetButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isPresetBuilderActive)
            {
                MessageBox.Show(this, "Save the active preset before importing another one.", "Import Preset", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            OpenFileDialog dialog = new OpenFileDialog
            {
                Title = "Import XtremeShell Preset",
                Filter = "XtremeShell preset (*.xspreset)|*.xspreset|JSON files (*.json)|*.json|All files (*.*)|*.*",
                DefaultExt = ".xspreset"
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            try
            {
                string json = File.ReadAllText(dialog.FileName);
                XtremeShellPreset? preset = JsonSerializer.Deserialize<XtremeShellPreset>(
                    json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (preset == null)
                {
                    throw new InvalidOperationException("The preset file is empty or invalid.");
                }

                if (!string.Equals(preset.XtremeShellVersion, CurrentXtremeShellVersion, StringComparison.Ordinal))
                {
                    MessageBox.Show(
                        this,
                        "This preset cannot be used." +
                        ".\n\nOnly presets created with XtremeShell " + CurrentXtremeShellVersion + " can be imported.",
                        "Version mismatch",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                    return;
                }

                foreach (PresetEntry entry in preset.Entries)
                {
                    entry.IsSelected = true;
                }

                PresetImportWindow window = new PresetImportWindow(this, preset)
                {
                    Owner = this
                };
                window.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Failed to import preset:\n\n" + ex.Message, "Import Preset", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SetPresetBuilderActive(bool isActive)
        {
            _isPresetBuilderActive = isActive;
            PresetBuilderFrame.Visibility = isActive ? Visibility.Visible : Visibility.Collapsed;
            PresetBuilderBar.Visibility = isActive ? Visibility.Visible : Visibility.Collapsed;
            CreatePresetButton.Content = isActive ? "Save Preset" : "Create Preset";
            InstallButton.Content = isActive ? "Add to Preset" : "Install Selected";

            if (isActive)
            {
                ClearHomeToggleStatesForPresetBuilder();
            }
            else
            {
                LoadHomeToggleStates();
            }
        }

        private void SaveCurrentPreset()
        {
            if (_presetEntries.Count == 0)
            {
                MessageBox.Show(this, "No changes were recorded for this preset.", "Create Preset", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            SaveFileDialog dialog = new SaveFileDialog
            {
                Title = "Save XtremeShell Preset",
                Filter = "XtremeShell preset (*.xspreset)|*.xspreset",
                DefaultExt = ".xspreset",
                AddExtension = true,
                FileName = "XtremeShellPreset.xspreset"
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            XtremeShellPreset preset = new XtremeShellPreset
            {
                XtremeShellVersion = CurrentXtremeShellVersion,
                CreatedAtUtc = DateTime.UtcNow,
                Entries = _presetEntries.ToList()
            };

            string json = JsonSerializer.Serialize(preset, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dialog.FileName, json, Encoding.UTF8);

            SetPresetBuilderActive(false);
            bmLog.Text = "Preset saved: " + dialog.FileName;
        }

        private async Task DiscardPresetBuilderAsync()
        {
            _presetEntries.Clear();
            _isPresetBuilderActive = false;

            PresetBuilderBarText.Text = "Preset discarded";
            PresetBuilderBar.Background = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#D03545")
            );

            PresetBuilderBar.IsHitTestVisible = false;

            var fadeOut = new DoubleAnimation
            {
                From = 1.0,
                To = 0.0,
                Duration = TimeSpan.FromSeconds(2),
                FillBehavior = FillBehavior.HoldEnd
            };

            var tcs = new TaskCompletionSource<bool>();

            fadeOut.Completed += (s, e) =>
            {
                tcs.TrySetResult(true);
            };

            PresetBuilderBar.BeginAnimation(OpacityProperty, fadeOut);
            PresetBuilderFrame.BeginAnimation(OpacityProperty, fadeOut);

            await tcs.Task;

            PresetBuilderBar.Visibility = Visibility.Collapsed;
            PresetBuilderFrame.Visibility = Visibility.Collapsed;

            PresetBuilderBar.BeginAnimation(OpacityProperty, null);
            PresetBuilderFrame.BeginAnimation(OpacityProperty, null);

            PresetBuilderBar.Opacity = 1.0;
            PresetBuilderFrame.Opacity = 1.0;

            PresetBuilderBarText.Text = "Preset Builder is active";
            PresetBuilderBar.Background = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#8B2635")
            );

            PresetBuilderBar.IsHitTestVisible = true;

            CreatePresetButton.Content = "Create Preset";

            bmLog.Text = "Preset discarded.";
        }

        private void PresetBuilderBar_MouseEnter(object sender, MouseEventArgs e)
        {
            PresetBuilderBarText.Text = "Exit Preset Builder";
            PresetBuilderBar.Background = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#D03545")
            );
            Task.Delay(1000);
        }

        private void PresetBuilderBar_MouseLeave(object sender, MouseEventArgs e)
        {
            PresetBuilderBarText.Text = "Preset Builder is active";
            PresetBuilderBar.Background = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#8B2635")
            );
        }

        private async void PresetBuilderBar_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            var result = MessageBox.Show(
                "Would you like to save this preset?\n\n",
                "Preset Builder",
                MessageBoxButton.YesNoCancel,
                MessageBoxImage.Question
            );

            if (result == MessageBoxResult.Yes)
            {
                SaveCurrentPreset();
            }
            else if (result == MessageBoxResult.No)
            {
                await DiscardPresetBuilderAsync();
            }
        }

        private bool IsPresetRecordableButton(string buttonName)
        {
            return buttonName is "UltPwrPl"
                or "StickyKeys"
                or "DisableAds"
                or "DisableTelemetry"
                or "CleanReBin"
                or "RepairChoco"
                or "DelTmpFls"
                or "ApplyUpdatePreset"
                or "UniEdge"
                or "installEdge"
                or "installVencord";
        }

        private void RecordHomeAction(Button button)
        {
            PresetEntry entry = new PresetEntry
            {
                Category = "Tweaks",
                ActionType = PresetActionTypes.HomeAction,
                TargetId = button.Name,
                Name = button.Content?.ToString() ?? button.Name
            };

            UpsertPresetEntry(entry);
            bmLog.Text = entry.Name + " added to preset.";
        }

        private void RecordTogglePresetEntry(CheckBox checkBox, bool enabled)
        {
            PresetEntry entry = new PresetEntry
            {
                Category = "Tweaks",
                ActionType = PresetActionTypes.Toggle,
                TargetId = checkBox.Name,
                Name = checkBox.Content?.ToString() ?? checkBox.Name,
                Enabled = enabled
            };

            UpsertPresetEntry(entry);
            bmLog.Text = entry.Name + " set to " + (enabled ? "enabled" : "disabled") + " in preset.";
        }

        private void RecordRemoveAppPresetEntries(IReadOnlyList<PackageInfo> selectedPackages)
        {
            foreach (PackageInfo package in selectedPackages)
            {
                PresetEntry entry = new PresetEntry
                {
                    Category = "Remove Apps",
                    ActionType = PresetActionTypes.RemoveApp,
                    TargetId = !string.IsNullOrWhiteSpace(package.PackageFullName) ? package.PackageFullName : package.DisplayName,
                    Name = package.DisplayName,
                    DisplayName = package.DisplayName,
                    Publisher = package.Publisher,
                    Version = package.Version,
                    UninstallString = package.UninstallString,
                    PackageType = package.Type.ToString(),
                    PackageFullName = package.PackageFullName,
                    PackageFamilyName = package.PackageFamilyName
                };

                UpsertPresetEntry(entry);
                package.IsSelected = false;
            }

            UpdateSelectionCount();
            bmLog.Text = selectedPackages.Count + " app removal(s) added to preset.";
        }

        private void RecordInstallPackagePresetEntries(IReadOnlyList<PackageItem> selectedPackages)
        {
            foreach (PackageItem package in selectedPackages)
            {
                string packageId = package.Title;
                PresetEntry entry = new PresetEntry
                {
                    Category = "Package Store",
                    ActionType = PresetActionTypes.InstallPackage,
                    TargetId = packageId,
                    Name = package.Summary.Length > 0 ? package.Summary : package.Title,
                    PackageId = packageId,
                    Version = package.Version
                };

                UpsertPresetEntry(entry);
                ApplyPackageSelection(package, false);
            }

            UpdateSelectedCount();
            bmLog.Text = selectedPackages.Count + " package install(s) added to preset.";
        }

        private void UpsertPresetEntry(PresetEntry entry)
        {
            string key = GetPresetEntryKey(entry);
            PresetEntry? existing = _presetEntries.FirstOrDefault(item => GetPresetEntryKey(item) == key);

            if (existing != null)
            {
                int index = _presetEntries.IndexOf(existing);
                _presetEntries[index] = entry;
                return;
            }

            _presetEntries.Add(entry);
        }

        private static string GetPresetEntryKey(PresetEntry entry)
        {
            return entry.ActionType + "|" + entry.TargetId;
        }

        private void InstallQueueScrollViewer_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (sender is ScrollViewer scrollViewer)
            {
                scrollViewer.ScrollToHorizontalOffset(
                    scrollViewer.HorizontalOffset - e.Delta
                );

                e.Handled = true;
            }
        }

        private void LoadHomeToggleStates()
        {
            _isLoadingToggleStates = true;

            try
            {
                cbClassicContextMenu.IsChecked = IsClassicContextMenuEnabled();
                cbPowerThrottling.IsChecked = IsPowerThrottlingEnabled();
                cbWindowsUpdate.IsChecked = IsWindowsUpdateEnabled();
                cbAnimations.IsChecked = IsAnimationsEnabled();
                cbDarkTheme.IsChecked = IsDarkThemeEnabled();
                cbWindowsCopilot.IsChecked = IsWindowsCopilotEnabled();
                cbShowFileExtensions.IsChecked = IsShowFileExtensionsEnabled();
                cbHibernation.IsChecked = IsHibernationEnabled();
                cbVerboseLogon.IsChecked = IsVerboseLogonEnabled();
                cbGameBar.IsChecked = IsGameBarEnabled();
                cbExplorerThisPC.IsChecked = IsExplorerThisPCEnabled();
                cbWindowsErrorReporting.IsChecked = IsWindowsErrorReportingEnabled();
            }
            finally
            {
                _isLoadingToggleStates = false;
            }
        }

        private void ClearHomeToggleStatesForPresetBuilder()
        {
            _isLoadingToggleStates = true;

            try
            {
                cbClassicContextMenu.IsChecked = null;
                cbPowerThrottling.IsChecked = null;
                cbWindowsUpdate.IsChecked = null;
                cbAnimations.IsChecked = null;
                cbDarkTheme.IsChecked = null;
                cbWindowsCopilot.IsChecked = null;
                cbShowFileExtensions.IsChecked = null;
                cbHibernation.IsChecked = null;
                cbVerboseLogon.IsChecked = null;
                cbGameBar.IsChecked = null;
                cbExplorerThisPC.IsChecked = null;
                cbWindowsErrorReporting.IsChecked = null;
            }
            finally
            {
                _isLoadingToggleStates = false;
            }
        }

        public async Task ApplyPresetEntryAsync(PresetEntry entry, Action<string> progress)
        {
            switch (entry.ActionType)
            {
                case PresetActionTypes.Toggle:
                    progress((entry.Enabled == true ? "Enabling " : "Disabling ") + entry.Name);
                    await Task.Run(() => ApplyToggleById(entry.TargetId, entry.Enabled == true));
                    break;

                case PresetActionTypes.BravePolicy:
                    progress("Updating Brave policy: " + entry.Name);
                    await Task.Run(() => ApplyBravePolicy(entry));
                    break;

                case PresetActionTypes.RemoveApp:
                    progress("Removing app: " + entry.Name);
                    await RemovePresetAppAsync(entry);
                    break;

                case PresetActionTypes.InstallPackage:
                    progress("Installing package: " + (entry.PackageId ?? entry.TargetId));
                    await CommandRunner.RunAsync("choco", "install " + (entry.PackageId ?? entry.TargetId) + " -y");
                    break;

                case PresetActionTypes.HomeAction:
                    progress("Running tweak: " + entry.Name);
                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (FindName(entry.TargetId) is Button button)
                        {
                            button_Click(button, new RoutedEventArgs());
                        }
                    });
                    await Task.Delay(500);
                    break;
            }
        }

        private void ApplyToggleById(string targetId, bool enabled)
        {
            switch (targetId)
            {
                case "cbClassicContextMenu":
                    ToggleClassicContextMenu(enabled);
                    break;
                case "cbPowerThrottling":
                    TogglePowerThrottling(enabled);
                    break;
                case "cbWindowsUpdate":
                    ToggleWindowsUpdate(enabled);
                    break;
                case "cbAnimations":
                    ToggleAnimations(enabled);
                    break;
                case "cbDarkTheme":
                    ToggleDarkTheme(enabled);
                    break;
                case "cbWindowsCopilot":
                    ToggleWindowsCopilot(enabled);
                    break;
                case "cbShowFileExtensions":
                    ToggleShowFileExtensions(enabled);
                    break;
                case "cbHibernation":
                    ToggleHibernation(enabled);
                    break;
                case "cbVerboseLogon":
                    ToggleVerboseLogon(enabled);
                    break;
                case "cbGameBar":
                    ToggleGameBar(enabled);
                    break;
                case "cbExplorerThisPC":
                    ToggleExplorerThisPC(enabled);
                    break;
                case "cbWindowsErrorReporting":
                    ToggleWindowsErrorReporting(enabled);
                    break;
            }
        }

        private static void ApplyBravePolicy(PresetEntry entry)
        {
            const string bravePolicyPath = @"SOFTWARE\Policies\BraveSoftware\Brave";

            using RegistryKey? key = Registry.LocalMachine.CreateSubKey(bravePolicyPath);
            if (key == null)
            {
                throw new InvalidOperationException("Could not open or create the Brave policy registry key.");
            }

            RegistryValueKind kind = Enum.TryParse(entry.ValueKind, out RegistryValueKind parsedKind)
                ? parsedKind
                : RegistryValueKind.String;

            object value = kind == RegistryValueKind.DWord && int.TryParse(entry.Value, out int dwordValue)
                ? (object)dwordValue
                : (object)(entry.Value ?? string.Empty);

            key.SetValue(entry.TargetId, value, kind);
        }

        private async Task RemovePresetAppAsync(PresetEntry entry)
        {
            PackageInfo package = new PackageInfo
            {
                DisplayName = entry.DisplayName ?? entry.Name,
                Publisher = entry.Publisher ?? string.Empty,
                Version = entry.Version ?? string.Empty,
                UninstallString = entry.UninstallString ?? string.Empty,
                PackageFullName = entry.PackageFullName ?? string.Empty,
                PackageFamilyName = entry.PackageFamilyName ?? string.Empty,
                Type = string.Equals(entry.PackageType, PackageType.Uwp.ToString(), StringComparison.OrdinalIgnoreCase)
                    ? PackageType.Uwp
                    : PackageType.Win32
            };

            if (package.Type == PackageType.Uwp)
            {
                await AppUninstallService.UninstallUwpAsync(package, PromptPackageInUseRetryAsync);
                return;
            }

            await Task.Run(() => AppUninstallService.UninstallWin32(package));
        }
    }
}
