using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;

namespace XtremeShell
{
    public class PackageItem : INotifyPropertyChanged
    {
        public string Title { get; set; } = string.Empty;
        public string Authors { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;

        private string _iconPath = string.Empty;
        public string IconPath
        {
            get => _iconPath;
            set
            {
                if (_iconPath == value) return;
                _iconPath = value;
                OnPropertyChanged(nameof(IconPath));
                OnPropertyChanged(nameof(IconVisibility));
                OnPropertyChanged(nameof(IconFallbackVisibility));
            }
        }

        public Visibility IconVisibility => string.IsNullOrWhiteSpace(IconPath) ? Visibility.Collapsed : Visibility.Visible;
        public Visibility IconFallbackVisibility => string.IsNullOrWhiteSpace(IconPath) ? Visibility.Visible : Visibility.Collapsed;

        private string _buttonText = "Select";
        public string ButtonText
        {
            get => _buttonText;
            set { _buttonText = value; OnPropertyChanged(nameof(ButtonText)); }
        }

        private bool _isButtonEnabled = true;
        public bool IsButtonEnabled
        {
            get => _isButtonEnabled;
            set { _isButtonEnabled = value; OnPropertyChanged(nameof(IsButtonEnabled)); }
        }

        private bool _isSelected;
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected == value) return;
                _isSelected = value;
                OnPropertyChanged(nameof(IsSelected));
                OnPropertyChanged(nameof(SelectedBadgeVisibility));
            }
        }

        private bool _isInstalled;
        public bool IsInstalled
        {
            get => _isInstalled;
            set
            {
                if (_isInstalled == value) return;
                _isInstalled = value;
                OnPropertyChanged(nameof(IsInstalled));
                OnPropertyChanged(nameof(InstalledBadgeVisibility));
            }
        }

        private bool _isUpdateAvailable;
        public bool IsUpdateAvailable
        {
            get => _isUpdateAvailable;
            set
            {
                if (_isUpdateAvailable == value) return;
                _isUpdateAvailable = value;
                OnPropertyChanged(nameof(IsUpdateAvailable));
                OnPropertyChanged(nameof(UpdateBadgeVisibility));
            }
        }

        public Visibility InstalledBadgeVisibility => IsInstalled ? Visibility.Visible : Visibility.Collapsed;
        public Visibility SelectedBadgeVisibility => IsSelected ? Visibility.Visible : Visibility.Collapsed;
        public Visibility UpdateBadgeVisibility => IsUpdateAvailable ? Visibility.Visible : Visibility.Collapsed;

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged(string name) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class PackageCategory
    {
        public string Name { get; set; } = string.Empty;
        public ObservableCollection<PackageItem> Packages { get; } = new ObservableCollection<PackageItem>();
        public string CountText => Packages.Count == 1 ? "1 app" : $"{Packages.Count} apps";
    }

    public class InstallQueueItem : INotifyPropertyChanged
    {
        private string _status = "Pending";

        public string Title { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;

        public string Status
        {
            get => _status;
            set
            {
                if (_status == value) return;
                _status = value;
                OnPropertyChanged(nameof(Status));
                OnPropertyChanged(nameof(StatusBrush));
                OnPropertyChanged(nameof(StatusBorderBrush));
            }
        }

        public Brush StatusBrush => Status switch
        {
            "Downloading" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2E5F87")),
            "Installing" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7A5A20")),
            "Installed" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2D6B2D")),
            "Failed" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#8B2635")),
            "Skipped" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#5A3E4A")),
            _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4A2E3A"))
        };

        public Brush StatusBorderBrush => Status switch
        {
            "Downloading" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3C7DAF")),
            "Installing" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A77A2C")),
            "Installed" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4A8B4A")),
            "Failed" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A53D4A")),
            "Skipped" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6B4C57")),
            _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6B4C57"))
        };

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string name) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
