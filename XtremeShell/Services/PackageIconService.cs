using System.IO;
using System.Net.Http;
using System.Text;
using System.Xml.Linq;
using IOPath = System.IO.Path;

namespace XtremeShell.Services
{
    public static class PackageIconService
    {
        private static readonly HttpClient IconHttpClient = new();

        private static readonly string PackageIconCacheDirectory =
            IOPath.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "XtremeShell",
                "Cache",
                "PackageIcons");

        public static string FindCachedPackageIcon(string packageId)
        {
            try
            {
                var safeName = GetSafePackageIconName(packageId);
                if (!Directory.Exists(PackageIconCacheDirectory))
                    return string.Empty;

                return Directory
                    .EnumerateFiles(PackageIconCacheDirectory, safeName + ".*")
                    .FirstOrDefault(path => IsSupportedIconExtension(IOPath.GetExtension(path))) ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        public static async Task LoadPackageIconAsync(PackageItem package)
        {
            try
            {
                Directory.CreateDirectory(PackageIconCacheDirectory);

                var iconUrl = await GetChocolateyIconUrlAsync(package);
                if (string.IsNullOrWhiteSpace(iconUrl) ||
                    !Uri.TryCreate(iconUrl, UriKind.Absolute, out var uri))
                    return;

                var response = await IconHttpClient.GetAsync(uri);
                if (!response.IsSuccessStatusCode)
                    return;

                var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
                var extension = GetIconExtension(uri, contentType);
                if (!IsSupportedIconExtension(extension))
                    return;

                var bytes = await response.Content.ReadAsByteArrayAsync();
                if (bytes.Length == 0)
                    return;

                var iconPath = IOPath.Combine(
                    PackageIconCacheDirectory,
                    GetSafePackageIconName(package.Title) + extension);

                await File.WriteAllBytesAsync(iconPath, bytes);
                package.IconPath = iconPath;
            }
            catch
            {
            }
        }

        private static async Task<string> GetChocolateyIconUrlAsync(PackageItem package)
        {
            var packageId = package.Title.Replace("'", "''");
            var version = package.Version.Replace("'", "''");
            var url = string.IsNullOrWhiteSpace(version)
                ? $"https://community.chocolatey.org/api/v2/FindPackagesById()?id='{packageId}'"
                : $"https://community.chocolatey.org/api/v2/Packages(Id='{packageId}',Version='{version}')";

            var xml = await IconHttpClient.GetStringAsync(url);
            var document = XDocument.Parse(xml);
            XNamespace data = "http://schemas.microsoft.com/ado/2007/08/dataservices";
            return document.Descendants(data + "IconUrl").FirstOrDefault()?.Value ?? string.Empty;
        }

        private static string GetSafePackageIconName(string packageId)
        {
            var invalid = IOPath.GetInvalidFileNameChars();
            var builder = new StringBuilder(packageId.Length);

            foreach (var c in packageId)
                builder.Append(invalid.Contains(c) ? '_' : c);

            return builder.ToString().ToLowerInvariant();
        }

        private static string GetIconExtension(Uri uri, string contentType)
        {
            var extension = IOPath.GetExtension(uri.AbsolutePath).ToLowerInvariant();
            if (IsSupportedIconExtension(extension))
                return extension;

            return contentType.ToLowerInvariant() switch
            {
                "image/png" => ".png",
                "image/jpeg" => ".jpg",
                "image/jpg" => ".jpg",
                "image/gif" => ".gif",
                "image/bmp" => ".bmp",
                "image/x-icon" => ".ico",
                "image/vnd.microsoft.icon" => ".ico",
                _ => string.Empty
            };
        }

        private static bool IsSupportedIconExtension(string extension)
        {
            return extension.Equals(".png", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".jpg", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".jpeg", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".gif", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".bmp", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".ico", StringComparison.OrdinalIgnoreCase);
        }
    }
}
