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
  Console.WriteLine("Enter numbers separated by commas (default: 1)");
  Console.Write("Selection: ");

  var raw = Console.ReadLine() ?? "";
  if (string.IsNullOrWhiteSpace(raw)) return new HashSet<int> { 1 };

  var selected = new HashSet<int>();
  var parts = raw.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
  foreach (var p in parts)
  {
    if (!int.TryParse(p, out var n)) continue;
    if (n < 1 || n > 5) continue;
    selected.Add(n);
  }

  if (selected.Count == 0) selected.Add(1);
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

static void OpenBrowserExtensionsPage(int browser)
{
  try
  {
    var info = browser switch
    {
      1 => new ProcessStartInfo { FileName = "chrome.exe", UseShellExecute = true },
      2 => new ProcessStartInfo { FileName = "msedge.exe", UseShellExecute = true },
      3 => new ProcessStartInfo { FileName = "brave.exe", UseShellExecute = true },
      4 => new ProcessStartInfo { FileName = "opera.exe", UseShellExecute = true },
      5 => new ProcessStartInfo { FileName = "firefox.exe", UseShellExecute = true },
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
  var root = Path.Combine(downloads, "FlickFuse-Extension");
  var chromiumZipPath = Path.Combine(root, "flickfuse-extension-chromium-latest.zip");
  var chromiumExtractPath = Path.Combine(root, "flickfuse-extension-chromium-latest");
  var firefoxZipPath = Path.Combine(root, "flickfuse-extension-firefox-latest.zip");
  var firefoxExtractPath = Path.Combine(root, "flickfuse-extension-firefox-latest");

  Directory.CreateDirectory(root);

  var needsChromiumPackage = selected.Contains(1) || selected.Contains(2) || selected.Contains(3) || selected.Contains(4);
  var needsFirefoxPackage = selected.Contains(5);

  if (needsChromiumPackage)
  {
    Console.WriteLine("Downloading Chromium package...");
    await DownloadFileAsync(ChromiumZipUrl, chromiumZipPath);
    ExtractZip(chromiumZipPath, chromiumExtractPath);
    Open(chromiumExtractPath);
  }

  if (needsFirefoxPackage)
  {
    Console.WriteLine("Downloading Firefox package...");
    await DownloadFileAsync(FirefoxZipUrl, firefoxZipPath);
    ExtractZip(firefoxZipPath, firefoxExtractPath);
    Open(firefoxExtractPath);
  }

  foreach (var browser in selected) OpenBrowserExtensionsPage(browser);

  Console.WriteLine("FlickFuse installer complete.");
  if (needsChromiumPackage)
  {
    Console.WriteLine("Chromium browsers (Chrome/Edge/Brave/Opera):");
    Console.WriteLine("1) Developer Mode ON  2) Load unpacked  3) Select folder:");
    Console.WriteLine(chromiumExtractPath);
    Console.WriteLine("Chrome URL: chrome://extensions/");
    Console.WriteLine("Edge URL: edge://extensions/");
    Console.WriteLine("Brave URL: brave://extensions/");
    Console.WriteLine("Opera URL: opera://extensions/");
  }
  if (needsFirefoxPackage)
  {
    Console.WriteLine("Firefox:");
    Console.WriteLine("Open about:debugging#/runtime/this-firefox and choose the manifest.json in:");
    Console.WriteLine(firefoxExtractPath);
  }
}
catch (Exception ex)
{
  Console.Error.WriteLine("Installer failed: " + ex.Message);
  Console.Error.WriteLine("Open this page for manual install: " + HelpUrl);
  try { Open(HelpUrl); } catch { }
  Environment.ExitCode = 1;
}
