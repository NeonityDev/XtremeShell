using System.ComponentModel;

namespace XtremeShell5
{
    public class PackageItem : INotifyPropertyChanged
    {
        public string Title { get; set; } = string.Empty;
        public string Authors { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;

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

        public bool IsSelected { get; set; }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string name) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
