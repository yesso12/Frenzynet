using System.Diagnostics;
using System.IO.Compression;
using System.Windows.Forms;

namespace FlickFuseInstaller;

internal static class Program
{
  [STAThread]
  static void Main()
  {
    ApplicationConfiguration.Initialize();
    Application.Run(new InstallerForm());
  }
}

internal sealed class InstallerForm : Form
{
  private const string ChromiumZipUrl = "https://frenzynets.com/frenzynet-updates/flickfuse-extension-chromium-latest.zip";
  private const string FirefoxZipUrl = "https://frenzynets.com/frenzynet-updates/flickfuse-extension-firefox-latest.zip";

  private readonly CheckBox _chrome = new() { Text = "Chrome", Checked = true, AutoSize = true };
  private readonly CheckBox _edge = new() { Text = "Edge", Checked = true, AutoSize = true };
  private readonly CheckBox _brave = new() { Text = "Brave", Checked = true, AutoSize = true };
  private readonly CheckBox _opera = new() { Text = "Opera", Checked = true, AutoSize = true };
  private readonly CheckBox _firefox = new() { Text = "Firefox", Checked = true, AutoSize = true };

  private readonly Button _installBtn = new() { Text = "Install Now", AutoSize = true };
  private readonly Button _openFolderBtn = new() { Text = "Open Install Folder", AutoSize = true, Enabled = false };
  private readonly Button _closeBtn = new() { Text = "Close", AutoSize = true };
  private readonly TextBox _log = new()
  {
    Multiline = true,
    ReadOnly = true,
    ScrollBars = ScrollBars.Vertical,
    Width = 680,
    Height = 250
  };

  private string _installRoot = string.Empty;

  internal InstallerForm()
  {
    Text = "FlickFuse Installer";
    Width = 740;
    Height = 520;
    FormBorderStyle = FormBorderStyle.FixedDialog;
    MaximizeBox = false;
    MinimizeBox = false;
    StartPosition = FormStartPosition.CenterScreen;

    var title = new Label
    {
      Text = "Select browsers to install FlickFuse extension",
      AutoSize = true,
      Font = new Font(Font, FontStyle.Bold)
    };

    var checks = new FlowLayoutPanel
    {
      FlowDirection = FlowDirection.LeftToRight,
      AutoSize = true,
      WrapContents = true,
      Width = 680
    };
    checks.Controls.AddRange(new Control[] { _chrome, _edge, _brave, _opera, _firefox });

    var buttons = new FlowLayoutPanel
    {
      FlowDirection = FlowDirection.LeftToRight,
      AutoSize = true,
      WrapContents = true,
      Width = 680
    };
    buttons.Controls.AddRange(new Control[] { _installBtn, _openFolderBtn, _closeBtn });

    var root = new FlowLayoutPanel
    {
      Dock = DockStyle.Fill,
      FlowDirection = FlowDirection.TopDown,
      WrapContents = false,
      AutoScroll = true,
      Padding = new Padding(16)
    };

    root.Controls.Add(title);
    root.Controls.Add(checks);
    root.Controls.Add(buttons);
    root.Controls.Add(_log);

    Controls.Add(root);

    _installBtn.Click += async (_, _) => await InstallAsync();
    _openFolderBtn.Click += (_, _) => OpenInstallRoot();
    _closeBtn.Click += (_, _) => Close();

    Log("Ready.");
  }

  private async Task InstallAsync()
  {
    var selected = GetSelectedBrowsers();
    if (selected.Count == 0)
    {
      MessageBox.Show(this, "Select at least one browser.", "FlickFuse Installer", MessageBoxButtons.OK, MessageBoxIcon.Warning);
      return;
    }

    ToggleUi(false);
    try
    {
      var downloads = ExpandPath("%USERPROFILE%\\Downloads");
      var tempRoot = Path.Combine(downloads, "FlickFuse-Extension-Temp");
      _installRoot = Path.Combine(ExpandPath("%LOCALAPPDATA%"), "FlickFuse", "Extensions");

      Directory.CreateDirectory(tempRoot);
      Directory.CreateDirectory(_installRoot);

      var chromiumZipPath = Path.Combine(tempRoot, "flickfuse-extension-chromium-latest.zip");
      var chromiumExtractPath = Path.Combine(tempRoot, "flickfuse-extension-chromium-latest");
      var firefoxZipPath = Path.Combine(tempRoot, "flickfuse-extension-firefox-latest.zip");
      var firefoxExtractPath = Path.Combine(tempRoot, "flickfuse-extension-firefox-latest");

      var needsChromium = selected.Any(b => b is BrowserKind.Chrome or BrowserKind.Edge or BrowserKind.Brave or BrowserKind.Opera);
      var needsFirefox = selected.Contains(BrowserKind.Firefox);

      if (needsChromium)
      {
        Log("Downloading Chromium package...");
        await DownloadFileAsync(ChromiumZipUrl, chromiumZipPath);
        ExtractZip(chromiumZipPath, chromiumExtractPath);

        if (selected.Contains(BrowserKind.Chrome)) CopyDirectory(chromiumExtractPath, Path.Combine(_installRoot, "chrome"));
        if (selected.Contains(BrowserKind.Edge)) CopyDirectory(chromiumExtractPath, Path.Combine(_installRoot, "edge"));
        if (selected.Contains(BrowserKind.Brave)) CopyDirectory(chromiumExtractPath, Path.Combine(_installRoot, "brave"));
        if (selected.Contains(BrowserKind.Opera)) CopyDirectory(chromiumExtractPath, Path.Combine(_installRoot, "opera"));
      }

      if (needsFirefox)
      {
        Log("Downloading Firefox package...");
        await DownloadFileAsync(FirefoxZipUrl, firefoxZipPath);
        ExtractZip(firefoxZipPath, firefoxExtractPath);
        CopyDirectory(firefoxExtractPath, Path.Combine(_installRoot, "firefox"));
      }

      Open(_installRoot);
      foreach (var browser in selected)
      {
        LaunchBrowser(browser);
      }

      Log("Install files placed successfully.");
      Log("Next step: in each browser, load unpacked extension from the browser-specific folder.");
      Log($"Install root: {_installRoot}");
      Log("Chrome: chrome://extensions/");
      Log("Edge: edge://extensions/");
      Log("Brave: brave://extensions/");
      Log("Opera: opera://extensions/");
      Log("Firefox: about:debugging#/runtime/this-firefox");
      _openFolderBtn.Enabled = true;
    }
    catch (Exception ex)
    {
      Log("Installer failed: " + ex.Message);
      MessageBox.Show(this, "Install failed. Please try again.", "FlickFuse Installer", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
    finally
    {
      ToggleUi(true);
    }
  }

  private List<BrowserKind> GetSelectedBrowsers()
  {
    var list = new List<BrowserKind>();
    if (_chrome.Checked) list.Add(BrowserKind.Chrome);
    if (_edge.Checked) list.Add(BrowserKind.Edge);
    if (_brave.Checked) list.Add(BrowserKind.Brave);
    if (_opera.Checked) list.Add(BrowserKind.Opera);
    if (_firefox.Checked) list.Add(BrowserKind.Firefox);
    return list;
  }

  private void ToggleUi(bool enabled)
  {
    _installBtn.Enabled = enabled;
    _chrome.Enabled = enabled;
    _edge.Enabled = enabled;
    _brave.Enabled = enabled;
    _opera.Enabled = enabled;
    _firefox.Enabled = enabled;
    Cursor = enabled ? Cursors.Default : Cursors.WaitCursor;
  }

  private void OpenInstallRoot()
  {
    if (!string.IsNullOrWhiteSpace(_installRoot) && Directory.Exists(_installRoot))
    {
      Open(_installRoot);
    }
  }

  private void Log(string line)
  {
    _log.AppendText($"[{DateTime.Now:HH:mm:ss}] {line}{Environment.NewLine}");
  }

  private static string ExpandPath(string p) => Environment.ExpandEnvironmentVariables(p);

  private static async Task DownloadFileAsync(string url, string outPath)
  {
    using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
    var bytes = await client.GetByteArrayAsync(url);
    await File.WriteAllBytesAsync(outPath, bytes);
  }

  private static void ExtractZip(string zipPath, string extractPath)
  {
    if (Directory.Exists(extractPath)) Directory.Delete(extractPath, true);
    ZipFile.ExtractToDirectory(zipPath, extractPath, true);
  }

  private static void CopyDirectory(string sourceDir, string destDir)
  {
    if (Directory.Exists(destDir)) Directory.Delete(destDir, true);
    Directory.CreateDirectory(destDir);

    foreach (var dirPath in Directory.GetDirectories(sourceDir, "*", SearchOption.AllDirectories))
    {
      Directory.CreateDirectory(dirPath.Replace(sourceDir, destDir));
    }

    foreach (var filePath in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
    {
      var targetPath = filePath.Replace(sourceDir, destDir);
      var parent = Path.GetDirectoryName(targetPath);
      if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
      File.Copy(filePath, targetPath, true);
    }
  }

  private static void Open(string target)
  {
    Process.Start(new ProcessStartInfo
    {
      FileName = target,
      UseShellExecute = true
    });
  }

  private void LaunchBrowser(BrowserKind browser)
  {
    try
    {
      var info = browser switch
      {
        BrowserKind.Chrome => new ProcessStartInfo { FileName = "chrome.exe", Arguments = "chrome://extensions/", UseShellExecute = true },
        BrowserKind.Edge => new ProcessStartInfo { FileName = "msedge.exe", Arguments = "edge://extensions/", UseShellExecute = true },
        BrowserKind.Brave => new ProcessStartInfo { FileName = "brave.exe", Arguments = "brave://extensions/", UseShellExecute = true },
        BrowserKind.Opera => new ProcessStartInfo { FileName = "opera.exe", Arguments = "opera://extensions/", UseShellExecute = true },
        BrowserKind.Firefox => new ProcessStartInfo { FileName = "firefox.exe", Arguments = "about:debugging#/runtime/this-firefox", UseShellExecute = true },
        _ => throw new InvalidOperationException("unknown_browser")
      };
      Process.Start(info);
    }
    catch
    {
      Log($"Could not launch {browser}. Open it manually.");
    }
  }
}

internal enum BrowserKind
{
  Chrome,
  Edge,
  Brave,
  Opera,
  Firefox
}
