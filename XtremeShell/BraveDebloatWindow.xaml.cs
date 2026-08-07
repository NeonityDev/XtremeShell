using Microsoft.Win32;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Windows;

namespace XtremeShell
{
    public partial class BraveDebloatWindow : Window
    {
        private const string BravePolicyPath = @"SOFTWARE\Policies\BraveSoftware\Brave";
        private readonly bool _presetBuilderMode;
        private readonly Action<IReadOnlyList<PresetEntry>>? _presetRecorder;

        public ObservableCollection<BraveDebloatOption> Options { get; private set; }

        public BraveDebloatWindow()
            : this(false, null)
        {
        }

        public BraveDebloatWindow(bool presetBuilderMode, Action<IReadOnlyList<PresetEntry>>? presetRecorder)
        {
            InitializeComponent();

            _presetBuilderMode = presetBuilderMode;
            _presetRecorder = presetRecorder;

            Options = new ObservableCollection<BraveDebloatOption>();
            DataContext = this;

            LoadOptions();
            LoadCurrentPolicyState();
            UpdateSelectionState();

            if (_presetBuilderMode)
            {
                Title = "Debloat Brave - Preset Builder";
                ApplyButton.Content = "Add to Preset";
                StatusText.Text = "Preset Builder is active.";
            }
        }

        private void LoadOptions()
        {
            AddOption("Disable Brave Sync", "SyncDisabled", 1);
            AddOption("Disable Tor Private Window", "TorDisabled", 1);
            AddOption("Enable Manifest V2 Extensions", "ExtensionManifestV2Availability", 2);
            AddOption("Disable Brave Rewards", "BraveRewardsDisabled", 1);
            AddOption("Disable Brave Wallet", "BraveWalletDisabled", 1);
            AddOption("Disable Brave VPN", "BraveVPNDisabled", 1);
            AddOption("Disable Brave Leo AI Chat", "BraveAIChatEnabled", 0);
            AddOption("Disable Brave Talk", "BraveTalkDisabled", 1);
            AddOption("Disable Brave News", "BraveNewsDisabled", 1);
            AddOption("Disable Brave Speedreader", "BraveSpeedreaderEnabled", 0);
            AddOption("Disable Brave Wayback Machine", "BraveWaybackMachineEnabled", 0);
            AddOption("Disable Brave Playlist", "BravePlaylistEnabled", 0);
            AddOption("Disable Brave Stats Ping", "BraveStatsPingEnabled", 0);
            AddOption("Disable Brave Web Discovery", "BraveWebDiscoveryEnabled", 0);
            AddOption("Disable Brave P3A Analytics", "BraveP3AEnabled", 0);
            AddOption("Disable Privacy Sandbox Ad Topics", "PrivacySandboxAdTopicsEnabled", 0);
            AddOption("Disable Privacy Sandbox Ad Measurement", "PrivacySandboxAdMeasurementEnabled", 0);
            AddOption("Disable Privacy Sandbox Prompt", "PrivacySandboxPromptEnabled", 0);
            AddOption("Block Geolocation", "DefaultGeolocationSetting", 2);
            AddOption("Block Notifications", "DefaultNotificationsSetting", 2);
            AddOption("Block Local Fonts Access", "DefaultLocalFontsSetting", 2);
            AddOption("Block Sensors Access", "DefaultSensorsSetting", 2);
            AddOption("Block Serial Port Access", "DefaultSerialGuardSetting", 2);
            AddOption("Block MIDI SysEx Access", "DefaultMidiSetting", 2);
            AddOption("Block Web Bluetooth Access", "DefaultWebBluetoothGuardSetting", 2);
            AddOption("Disable Cloud Reporting", "CloudReportingEnabled", 0);
            AddOption("Disable Google Drive Integration", "DriveDisabled", 1);
            AddOption("Disable Password Manager", "PasswordManagerEnabled", 0);
            AddOption("Disable Password Sharing", "PasswordSharingEnabled", 0);
            AddOption("Disable Password Leak Detection", "PasswordLeakDetectionEnabled", 0);
            AddOption("Disable Quick Answers", "QuickAnswersEnabled", 0);
            AddOption("Disable Safe Browsing Extended Reporting", "SafeBrowsingExtendedReportingEnabled", 0);
            AddOption("Disable Safe Browsing Surveys", "SafeBrowsingSurveysEnabled", 0);
            AddOption("Disable Safe Browsing Deep Scanning", "SafeBrowsingDeepScanningEnabled", 0);
            AddOption("Disable Device Activity Heartbeat", "DeviceActivityHeartbeatEnabled", 0);
            AddOption("Disable Device Metrics Reporting", "DeviceMetricsReportingEnabled", 0);
            AddOption("Disable Browser Heartbeat", "HeartbeatEnabled", 0);
            AddOption("Disable Log Upload", "LogUploadEnabled", 0);
            AddOption("Disable App Inventory Reporting", "ReportAppInventory", "");
            AddOption("Disable Device Activity Time Reporting", "ReportDeviceActivityTimes", 0);
            AddOption("Disable Device App Info Reporting", "ReportDeviceAppInfo", 0);
            AddOption("Disable Device System Info Reporting", "ReportDeviceSystemInfo", 0);
            AddOption("Disable Device User Reporting", "ReportDeviceUsers", 0);
            AddOption("Disable Website Telemetry Reporting", "ReportWebsiteTelemetry", "");
            AddOption("Disable Alternate Error Pages", "AlternateErrorPagesEnabled", 0);
            AddOption("Disable Credit Card Autofill", "AutofillCreditCardEnabled", 0);
            AddOption("Disable Background Mode", "BackgroundModeEnabled", 0);
            AddOption("Disable Guest Mode", "BrowserGuestModeEnabled", 0);
            AddOption("Disable Browser Sign-In", "BrowserSignin", 0);
            AddOption("Disable Built-In DNS Client", "BuiltInDnsClientEnabled", 0);
            AddOption("Disable Default Browser Prompt", "DefaultBrowserSettingEnabled", 0);
            AddOption("Disable Metrics Reporting", "MetricsReportingEnabled", 0);
            AddOption("Disable Parcel Tracking", "ParcelTrackingEnabled", 0);
            AddOption("Disable Related Website Sets", "RelatedWebsiteSetsEnabled", 0);
            AddOption("Disable Shopping List", "ShoppingListEnabled", 0);
        }

        private void AddOption(string friendlyName, string valueName, int value)
        {
            BraveDebloatOption option = new BraveDebloatOption(
                friendlyName,
                valueName,
                value,
                RegistryValueKind.DWord
            );

            option.PropertyChanged += Option_PropertyChanged;
            Options.Add(option);
        }

        private void AddOption(string friendlyName, string valueName, string value)
        {
            BraveDebloatOption option = new BraveDebloatOption(
                friendlyName,
                valueName,
                value,
                RegistryValueKind.String
            );

            option.PropertyChanged += Option_PropertyChanged;
            Options.Add(option);
        }

        private void LoadCurrentPolicyState()
        {
            try
            {
                using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(BravePolicyPath))
                {
                    if (key == null)
                    {
                        StatusText.Text = "No Brave policies found.";
                        return;
                    }

                    foreach (BraveDebloatOption option in Options)
                    {
                        object? currentValue = key.GetValue(option.ValueName);

                        if (currentValue == null)
                        {
                            option.IsSelected = false;
                            continue;
                        }

                        option.IsSelected = RegistryValueMatches(option, currentValue);
                    }
                }

                StatusText.Text = "Ready";
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error: could not read Brave policies";

                MessageBox.Show(
                    this,
                    "Failed to read current Brave policies:\n\n" + ex.Message,
                    "Debloat Brave",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );
            }
        }

        private static bool RegistryValueMatches(BraveDebloatOption option, object currentValue)
        {
            if (option.ValueKind == RegistryValueKind.DWord)
            {
                try
                {
                    return Convert.ToInt32(currentValue) == Convert.ToInt32(option.Value);
                }
                catch
                {
                    return false;
                }
            }

            if (option.ValueKind == RegistryValueKind.String)
            {
                string? currentString = currentValue as string;
                string? expectedString = option.Value as string;

                return string.Equals(
                    currentString ?? string.Empty,
                    expectedString ?? string.Empty,
                    StringComparison.Ordinal
                );
            }

            return false;
        }

        private void Option_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(BraveDebloatOption.IsSelected))
            {
                UpdateSelectionState();
            }
        }

        private void SelectAllButton_Click(object sender, RoutedEventArgs e)
        {
            bool shouldSelectAll = Options.Any(option => !option.IsSelected);

            foreach (BraveDebloatOption option in Options)
            {
                option.IsSelected = shouldSelectAll;
            }

            UpdateSelectionState();
        }

        private void ApplyButton_Click(object sender, RoutedEventArgs e)
        {
            if (_presetBuilderMode)
            {
                List<PresetEntry> entries = Options
                    .Where(option => option.IsSelected)
                    .Select(option => option.ToPresetEntry())
                    .ToList();

                _presetRecorder?.Invoke(entries);
                StatusText.Text = entries.Count + " Brave option(s) added to preset.";
                Close();
                return;
            }

            if (!IsRunningAsAdministrator())
            {
                MessageBox.Show(
                    this,
                    "This action requires administrator privileges because it writes to HKEY_LOCAL_MACHINE.\n\nPlease restart XtremeShell as administrator and try again.",
                    "Administrator rights required",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning
                );

                StatusText.Text = "Administrator rights required.";
                return;
            }

            try
            {
                int disabledCount = 0;
                int enabledAgainCount = 0;

                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(BravePolicyPath))
                {
                    if (key == null)
                    {
                        throw new InvalidOperationException("Could not open or create the Brave policy registry key.");
                    }

                    foreach (BraveDebloatOption option in Options)
                    {
                        if (option.IsSelected)
                        {
                            key.SetValue(option.ValueName, option.Value, option.ValueKind);
                            disabledCount++;
                        }
                        else
                        {
                            if (key.GetValue(option.ValueName) != null)
                            {
                                key.DeleteValue(option.ValueName, false);
                                enabledAgainCount++;
                            }
                        }
                    }
                }

                StatusText.Text = disabledCount + " disabled, " + enabledAgainCount + " restored. Restart Brave.";

                MessageBox.Show(
                    this,
                    "Brave policies were updated successfully.\n\nDisabled: " + disabledCount +
                    "\nRestored: " + enabledAgainCount +
                    "\n\nRestart Brave for the changes to take effect.",
                    "Debloat Brave",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );
            }
            catch (Exception ex)
            {
                StatusText.Text = "Failed to update Brave policies.";

                MessageBox.Show(
                    this,
                    "Failed to update Brave policies:\n\n" + ex.Message,
                    "Debloat Brave",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void UpdateSelectionState()
        {
            if (Options == null || SelectedCountText == null || SelectAllButton == null || ApplyButton == null)
            {
                return;
            }

            int selectedCount = Options.Count(option => option.IsSelected);
            int totalCount = Options.Count;

            SelectedCountText.Text = selectedCount + " of " + totalCount + " policies selected";
            SelectAllButton.Content = selectedCount == totalCount && totalCount > 0
                ? "Unselect All"
                : "Select All";

            ApplyButton.IsEnabled = true;
        }

        private static bool IsRunningAsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }

    public class BraveDebloatOption : INotifyPropertyChanged
    {
        private bool _isSelected;

        public string FriendlyName { get; private set; }
        public string ValueName { get; private set; }
        public object Value { get; private set; }
        public RegistryValueKind ValueKind { get; private set; }

        public bool IsSelected
        {
            get { return _isSelected; }
            set
            {
                if (_isSelected == value)
                {
                    return;
                }

                _isSelected = value;
                OnPropertyChanged();
            }
        }

        public BraveDebloatOption(
            string friendlyName,
            string valueName,
            object value,
            RegistryValueKind valueKind)
        {
            FriendlyName = friendlyName;
            ValueName = valueName;
            Value = value;
            ValueKind = valueKind;
        }

        public PresetEntry ToPresetEntry()
        {
            return new PresetEntry
            {
                Category = "Brave Debloat",
                ActionType = PresetActionTypes.BravePolicy,
                TargetId = ValueName,
                Name = FriendlyName,
                Value = Value?.ToString() ?? string.Empty,
                ValueKind = ValueKind.ToString()
            };
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChangedEventHandler? handler = PropertyChanged;

            if (handler != null)
            {
                handler(this, new PropertyChangedEventArgs(propertyName));
            }
        }
    }
}
