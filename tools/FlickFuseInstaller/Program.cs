using System.Diagnostics;
using System.IO.Compression;

const string ChromiumZipUrl = "https://frenzynets.com/frenzynet-updates/flickfuse-extension-chromium-latest.zip";
const string FirefoxZipUrl = "https://frenzynets.com/frenzynet-updates/flickfuse-extension-firefox-latest.zip";
const string HelpUrl = "https://frenzynets.com/frenzynet-updates/";

static string ExpandPath(string p) => Environment.ExpandEnvironmentVariables(p);

static void Open(string target)
{
  Process.Start(new ProcessStartInfo
  {
    FileName = target,
    UseShellExecute = true
  });
}

static HashSet<int> ReadBrowserSelection()
{
  Console.WriteLine("Choose browsers to install FlickFuse for:");
  Console.WriteLine("1) Chrome");
  Console.WriteLine("2) Edge");
  Console.WriteLine("3) Brave");
  Console.WriteLine("4) Opera");
  Console.WriteLine("5) Firefox");
  Console.WriteLine("Enter numbers separated by commas, or A for all (default: all)");
  Console.Write("Selection: ");

  var raw = Console.ReadLine() ?? "";
  if (string.IsNullOrWhiteSpace(raw)) return new HashSet<int> { 1, 2, 3, 4, 5 };
  if (string.Equals(raw.Trim(), "A", StringComparison.OrdinalIgnoreCase))
  {
    return new HashSet<int> { 1, 2, 3, 4, 5 };
  }

  var selected = new HashSet<int>();
  var parts = raw.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
  foreach (var p in parts)
  {
    if (!int.TryParse(p, out var n)) continue;
    if (n < 1 || n > 5) continue;
    selected.Add(n);
  }

  if (selected.Count == 0) return new HashSet<int> { 1, 2, 3, 4, 5 };
  return selected;
}

static async Task DownloadFileAsync(string url, string outPath)
{
  using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
  var bytes = await client.GetByteArrayAsync(url);
  await File.WriteAllBytesAsync(outPath, bytes);
}

static void ExtractZip(string zipPath, string extractPath)
{
  if (Directory.Exists(extractPath)) Directory.Delete(extractPath, true);
  ZipFile.ExtractToDirectory(zipPath, extractPath, true);
}

static void CopyDirectory(string sourceDir, string destDir)
{
  if (Directory.Exists(destDir)) Directory.Delete(destDir, true);
  Directory.CreateDirectory(destDir);
  foreach (var dirPath in Directory.GetDirectories(sourceDir, "*", SearchOption.AllDirectories))
  {
    Directory.CreateDirectory(dirPath.Replace(sourceDir, destDir));
  }
  foreach (var filePath in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
  {
    var target = filePath.Replace(sourceDir, destDir);
    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
    File.Copy(filePath, target, true);
  }
}

static void OpenBrowserExtensionsPage(int browser)
{
  try
  {
    var info = browser switch
    {
      1 => new ProcessStartInfo { FileName = "chrome.exe", Arguments = "chrome://extensions/", UseShellExecute = true },
      2 => new ProcessStartInfo { FileName = "msedge.exe", Arguments = "edge://extensions/", UseShellExecute = true },
      3 => new ProcessStartInfo { FileName = "brave.exe", Arguments = "brave://extensions/", UseShellExecute = true },
      4 => new ProcessStartInfo { FileName = "opera.exe", Arguments = "opera://extensions/", UseShellExecute = true },
      5 => new ProcessStartInfo { FileName = "firefox.exe", Arguments = "about:debugging#/runtime/this-firefox", UseShellExecute = true },
      _ => throw new InvalidOperationException("unknown_browser")
    };
    Process.Start(info);
  }
  catch
  {
    Console.WriteLine($"Could not auto-open selected browser ({browser}).");
  }
}

try
{
  var selected = ReadBrowserSelection();
  var downloads = ExpandPath("%USERPROFILE%\\Downloads");
  var root = Path.Combine(downloads, "FlickFuse-Extension-Temp");
  var installRoot = Path.Combine(ExpandPath("%LOCALAPPDATA%"), "FlickFuse", "Extensions");
  var chromiumZipPath = Path.Combine(root, "flickfuse-extension-chromium-latest.zip");
  var chromiumExtractPath = Path.Combine(root, "flickfuse-extension-chromium-latest");
  var firefoxZipPath = Path.Combine(root, "flickfuse-extension-firefox-latest.zip");
  var firefoxExtractPath = Path.Combine(root, "flickfuse-extension-firefox-latest");

  Directory.CreateDirectory(root);
  Directory.CreateDirectory(installRoot);

  var needsChromiumPackage = selected.Contains(1) || selected.Contains(2) || selected.Contains(3) || selected.Contains(4);
  var needsFirefoxPackage = selected.Contains(5);

  if (needsChromiumPackage)
  {
    Console.WriteLine("Downloading Chromium package...");
    await DownloadFileAsync(ChromiumZipUrl, chromiumZipPath);
    ExtractZip(chromiumZipPath, chromiumExtractPath);
    if (selected.Contains(1)) CopyDirectory(chromiumExtractPath, Path.Combine(installRoot, "chrome"));
    if (selected.Contains(2)) CopyDirectory(chromiumExtractPath, Path.Combine(installRoot, "edge"));
    if (selected.Contains(3)) CopyDirectory(chromiumExtractPath, Path.Combine(installRoot, "brave"));
    if (selected.Contains(4)) CopyDirectory(chromiumExtractPath, Path.Combine(installRoot, "opera"));
  }

  if (needsFirefoxPackage)
  {
    Console.WriteLine("Downloading Firefox package...");
    await DownloadFileAsync(FirefoxZipUrl, firefoxZipPath);
    ExtractZip(firefoxZipPath, firefoxExtractPath);
    CopyDirectory(firefoxExtractPath, Path.Combine(installRoot, "firefox"));
  }

  Open(installRoot);
  foreach (var browser in selected) OpenBrowserExtensionsPage(browser);

  Console.WriteLine("FlickFuse installer complete.");
  if (needsChromiumPackage)
  {
    Console.WriteLine("Chromium browsers (Chrome/Edge/Brave/Opera):");
    Console.WriteLine("1) Developer Mode ON  2) Load unpacked  3) Select folder:");
    Console.WriteLine(Path.Combine(installRoot, "chrome"));
    Console.WriteLine("Chrome URL: chrome://extensions/");
    Console.WriteLine("Edge URL: edge://extensions/");
    Console.WriteLine("Brave URL: brave://extensions/");
    Console.WriteLine("Opera URL: opera://extensions/");
  }
  if (needsFirefoxPackage)
  {
    Console.WriteLine("Firefox:");
    Console.WriteLine("Open about:debugging#/runtime/this-firefox and choose the manifest.json in:");
    Console.WriteLine(Path.Combine(installRoot, "firefox"));
  }
  Console.WriteLine("Press Enter to close...");
  Console.ReadLine();
}
catch (Exception ex)
{
  Console.Error.WriteLine("Installer failed: " + ex.Message);
  Console.Error.WriteLine("Open this page for manual install: " + HelpUrl);
  try { Open(HelpUrl); } catch { }
  Environment.ExitCode = 1;
}
