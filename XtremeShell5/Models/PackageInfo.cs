using System.ComponentModel;

namespace XtremeShell5
{
    public enum PackageType { Win32, Uwp }

    public class PackageInfo : INotifyPropertyChanged
    {
        public string DisplayName { get; set; } = string.Empty;
        public string Publisher { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string UninstallString { get; set; } = string.Empty; // Win32 only
        public string ProductCode { get; set; } = string.Empty;     // Win32 only
        public PackageType Type { get; set; }
        public string PackageFullName { get; set; } = string.Empty; // UWP
        public string PackageFamilyName { get; set; } = string.Empty; // UWP

        private bool _isSelected;
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected != value)
                {
                    _isSelected = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
                }
            }
        }

        public event PropertyChangedEventHandler PropertyChanged = delegate { };
    }
}
