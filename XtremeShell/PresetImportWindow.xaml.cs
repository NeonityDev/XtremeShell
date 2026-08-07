using System.Collections.ObjectModel;
using System.Windows;

namespace XtremeShell
{
    public partial class PresetImportWindow : Window
    {
        private readonly MainWindow _mainWindow;
        private readonly XtremeShellPreset _preset;

        public ObservableCollection<PresetCategoryGroup> Groups { get; } = new();

        public PresetImportWindow(MainWindow mainWindow, XtremeShellPreset preset)
        {
            InitializeComponent();

            _mainWindow = mainWindow;
            _preset = preset;

            DataContext = this;
            BuildGroups();

            if(_preset.Entries.Count > 1) PresetSummary.Text = $"{_preset.Entries.Count} changes";
            if (_preset.Entries.Count == 1) PresetSummary.Text = $"{_preset.Entries.Count} change";

        }

        private void BuildGroups()
        {
            Groups.Clear();

            foreach (var group in _preset.Entries.GroupBy(entry => entry.Category))
            {
                Groups.Add(new PresetCategoryGroup
                {
                    Name = group.Key,
                    Items = new ObservableCollection<PresetEntry>(group)
                });
            }
        }

        private async void ApplyButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedEntries = Groups
                .SelectMany(group => group.Items)
                .Where(entry => entry.IsSelected)
                .ToList();

            if (selectedEntries.Count == 0)
            {
                MessageBox.Show(this, "No preset items are selected.", "Import Preset", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            ApplyButton.IsEnabled = false;
            StatusText.Text = "Applying preset...";
            ProgressLogPanel.Visibility = Visibility.Visible;
            ProgressLog.Text = string.Empty;

            foreach (var entry in selectedEntries)
            {
                AppendProgress("Applying: " + entry.Name);
                StatusText.Text = entry.Name;

                try
                {
                    await _mainWindow.ApplyPresetEntryAsync(entry, AppendProgress);
                    AppendProgress("Done: " + entry.Name);
                }
                catch (Exception ex)
                {
                    AppendProgress("Failed: " + entry.Name + " - " + ex.Message);
                }
            }

            StatusText.Text = "Preset applied.";
            ApplyButton.Visibility = Visibility.Collapsed;
        }

        private void AppendProgress(string text)
        {
            Dispatcher.Invoke(() =>
            {
                ProgressLog.AppendText(text + Environment.NewLine);
                ProgressLog.ScrollToEnd();
            });
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void CloseXtremeShellButton_Click(object sender, RoutedEventArgs e)
        {
            _mainWindow.Close();
        }
    }
}
