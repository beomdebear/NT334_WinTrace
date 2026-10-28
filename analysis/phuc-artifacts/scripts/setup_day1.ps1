# Ngày 1 – Tạo cấu trúc case và tải Eric Zimmerman Tools
# Chạy: PowerShell (Run as Administrator)
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\setup_day1.ps1

param(
    [string]$CaseRoot = "C:\case01",
    [string]$ToolDir  = "C:\Tools\EZ"
)

$ErrorActionPreference = "Stop"

# 1. Cấu trúc thư mục
$dirs = @(
    "evidence_raw",
    "evidence_work\hives", "evidence_work\Prefetch", "evidence_work\Recent",
    "evidence_work\RecycleBin", "evidence_work\JumpLists",
    "output\sbecmd", "output\pecmd", "output\lecmd", "output\rbcmd", "output\jlecmd",
    "findings", "notes\img"
)
foreach ($d in $dirs) { New-Item -ItemType Directory -Force -Path (Join-Path $CaseRoot $d) | Out-Null }
New-Item -ItemType Directory -Force -Path $ToolDir | Out-Null
Write-Host "[+] Đã tạo cấu trúc $CaseRoot"

# 2. Tải Get-ZimmermanTools và chạy
$script = Join-Path $ToolDir "Get-ZimmermanTools.ps1"
$url = "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"
try {
    Invoke-WebRequest -Uri $url -OutFile $script -UseBasicParsing
    Write-Host "[+] Đã tải Get-ZimmermanTools.ps1, đang tải bộ tool (vài phút)..."
    & $script -Dest $ToolDir
} catch {
    Write-Warning "Không tải được tự động. Vào https://ericzimmerman.github.io/ tải Get-ZimmermanTools thủ công, giải nén vào $ToolDir rồi chạy lại."
}

# 3. Kiểm tra các tool cần cho tuần 1
$need = "SBECmd.exe","PECmd.exe","LECmd.exe","RBCmd.exe","JLECmd.exe"
foreach ($t in $need) {
    $f = Get-ChildItem -Path $ToolDir -Recurse -Filter $t -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($f) { Write-Host "[OK] $t -> $($f.FullName)" } else { Write-Warning "[THIẾU] $t" }
}
Write-Host "`nGUI cần có: RegistryExplorer, ShellBagsExplorer, TimelineExplorer (nằm trong $ToolDir)."
Write-Host "Nếu tool báo thiếu .NET: cài .NET Desktop Runtime đúng phiên bản tool yêu cầu."

# 4. Ghi phiên bản tool vào notes
$log = Join-Path $CaseRoot "notes\tool_versions.md"
"# Tool versions – $(Get-Date -Format 'yyyy-MM-dd HH:mm') (local)`n" | Out-File $log -Encoding utf8
Get-ChildItem -Path $ToolDir -Recurse -Include *.exe | ForEach-Object {
    "- $($_.Name): $($_.VersionInfo.FileVersion)" | Out-File $log -Append -Encoding utf8
}
Write-Host "[+] Đã ghi phiên bản tool vào $log"
Write-Host "`nViệc tay còn lại: cài FTK Imager + 7-Zip, bắt đầu tải dataset Data Leakage Case."
