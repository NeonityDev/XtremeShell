using System.Collections.ObjectModel;
using System.Windows;

namespace XtremeShell
{
    public partial class MainWindow : Window
    {
        /// <summary>
        /// Interaction logic for MainWindow.xaml
        /// </summary>
        private ObservableCollection<PackageInfo> packages = new ObservableCollection<PackageInfo>();
        private ObservableCollection<PackageInfo> filteredPackages = new ObservableCollection<PackageInfo>();
        private ObservableCollection<PackageItem> _packages = new ObservableCollection<PackageItem>();
        private ObservableCollection<PackageItem> _selectedPackages = new ObservableCollection<PackageItem>();
        private readonly ObservableCollection<PackageCategory> _packageCategories = new ObservableCollection<PackageCategory>();
        private readonly ObservableCollection<InstallQueueItem> _installQueue = new ObservableCollection<InstallQueueItem>();
        private readonly Dictionary<string, InstallQueueItem> _installQueueByTitle = new Dictionary<string, InstallQueueItem>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _installedPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _outdatedPackageIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private bool _isSearching = false;
        private bool _exitRequested = false;
        private bool _isLoadingToggleStates = true;
        private bool _isPresetBuilderActive = false;
        private readonly ObservableCollection<PresetEntry> _presetEntries = new ObservableCollection<PresetEntry>();
        private bool _packageStateCacheLoaded = false;

        private bool _suppressSearch = true;
        public MainWindow()
        {
            InitializeComponent();
            Loaded += MainWindow_Loaded;
            InitializePackageManager();
            LoadHomeToggleStates();

            InstallPackageList.ItemsSource = _packageCategories;
            InstallQueueList.ItemsSource = _installQueue;

            Dispatcher.BeginInvoke(new Action(() =>
            {
                ShowDefaultPackages();
                _suppressSearch = false;
            }), System.Windows.Threading.DispatcherPriority.Loaded);
        }
    }
}
