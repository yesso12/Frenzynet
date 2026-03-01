using System.Diagnostics;
using System.IO.Compression;

const string ZipUrl = "https://frenzynets.com/frenzynet-updates/flickfuse-extension-chromium-latest.zip";
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

try
{
  var downloads = ExpandPath("%USERPROFILE%\\Downloads");
  var root = Path.Combine(downloads, "FlickFuse-Extension");
  var zipPath = Path.Combine(root, "flickfuse-extension-chromium-latest.zip");
  var extractPath = Path.Combine(root, "flickfuse-extension-chromium-latest");

  Directory.CreateDirectory(root);

  using (var client = new HttpClient())
  {
    client.Timeout = TimeSpan.FromMinutes(5);
    var bytes = await client.GetByteArrayAsync(ZipUrl);
    await File.WriteAllBytesAsync(zipPath, bytes);
  }

  if (Directory.Exists(extractPath)) Directory.Delete(extractPath, true);
  ZipFile.ExtractToDirectory(zipPath, extractPath, true);

  Open(extractPath);

  // Open common Chromium extension manager pages.
  foreach (var url in new[] { "chrome://extensions/", "edge://extensions/", "brave://extensions/", "opera://extensions/" })
  {
    try { Open(url); } catch { }
  }

  Console.WriteLine("FlickFuse installer complete.");
  Console.WriteLine("1) Developer Mode ON  2) Load unpacked  3) Select extracted folder:");
  Console.WriteLine(extractPath);
}
catch (Exception ex)
{
  Console.Error.WriteLine("Installer failed: " + ex.Message);
  Console.Error.WriteLine("Open this page for manual install: " + HelpUrl);
  try { Open(HelpUrl); } catch { }
  Environment.ExitCode = 1;
}
