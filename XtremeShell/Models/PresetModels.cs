using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace XtremeShell
{
    public class XtremeShellPreset
    {
        public string XtremeShellVersion { get; set; } = string.Empty;
        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
        public List<PresetEntry> Entries { get; set; } = new();
    }

    public class PresetEntry : INotifyPropertyChanged
    {
        private bool _isSelected = true;

        public string Category { get; set; } = string.Empty;
        public string ActionType { get; set; } = string.Empty;
        public string TargetId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public bool? Enabled { get; set; }
        public string? Value { get; set; }
        public string? ValueKind { get; set; }
        public string? PackageId { get; set; }
        public string? DisplayName { get; set; }
        public string? Publisher { get; set; }
        public string? Version { get; set; }
        public string? UninstallString { get; set; }
        public string? PackageType { get; set; }
        public string? PackageFullName { get; set; }
        public string? PackageFamilyName { get; set; }

        [JsonIgnore]
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected == value) return;
                _isSelected = value;
                OnPropertyChanged();
            }
        }

        [JsonIgnore]
        public string Detail
        {
            get
            {
                if (ActionType == PresetActionTypes.Toggle && Enabled.HasValue)
                {
                    return Enabled.Value ? "Enable" : "Disable";
                }

                if (ActionType == PresetActionTypes.InstallPackage)
                {
                    return PackageId ?? TargetId;
                }

                if (ActionType == PresetActionTypes.RemoveApp)
                {
                    return Publisher ?? PackageType ?? string.Empty;
                }

                if (ActionType == PresetActionTypes.BravePolicy)
                {
                    return TargetId;
                }

                return TargetId;
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class PresetCategoryGroup
    {
        public string Name { get; set; } = string.Empty;
        public ObservableCollection<PresetEntry> Items { get; set; } = new();
    }

    public static class PresetActionTypes
    {
        public const string Toggle = "Toggle";
        public const string HomeAction = "HomeAction";
        public const string BravePolicy = "BravePolicy";
        public const string RemoveApp = "RemoveApp";
        public const string InstallPackage = "InstallPackage";
    }
}
