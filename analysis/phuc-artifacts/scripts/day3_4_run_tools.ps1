# Ngày 3–4 – Chạy SBECmd, LECmd, JLECmd, PECmd, RBCmd
# - ShellBags, Recycle Bin: đọc bản copy trong evidence_work (timestamp nằm bên trong artifact)
# - LNK, Jump Lists, Prefetch: đọc TRỰC TIẾP ổ image đã mount read-only (-Drive) để giữ
#   Created/Accessed của file .lnk/.pf – Copy-Item làm mất các timestamp này.
# Mọi lệnh được ghi vào notes\command_log.md (phục vụ tái lập)
# Chạy: .\day3_4_run_tools.ps1 -Drive F: -User informant -CaseRoot "D:\...\case01" -ToolDir "D:\...\Tools\EZ"

param(
    [Parameter(Mandatory=$true)][string]$Drive,
    [string]$User     = "informant",
    [string]$CaseRoot = "C:\case01",
    [string]$ToolDir  = "C:\Tools\EZ"
)

$Drive = $Drive.TrimEnd('\')
$recent = "$Drive\Users\$User\AppData\Roaming\Microsoft\Windows\Recent"
if (-not (Test-Path $recent)) { Write-Error "Không thấy $recent – kiểm tra ổ mount và tên user."; exit 1 }

$work = Join-Path $CaseRoot "evidence_work"
$out  = Join-Path $CaseRoot "output"
$log  = Join-Path $CaseRoot "notes\command_log.md"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"

function Find-Tool($name) {
    $f = Get-ChildItem -Path $ToolDir -Recurse -Filter $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $f) { Write-Warning "Không tìm thấy $name trong $ToolDir"; return $null }
    return $f.FullName
}

function Run($exe, [string[]]$toolArgs) {
    if (-not $exe) { return }
    $line = "`"$exe`" " + ($toolArgs -join " ")
    "`n## $((Get-Date).ToUniversalTime().ToString('u'))`n``````$line``````" | Out-File $log -Append -Encoding utf8
    Write-Host ">> $line"
    & $exe @toolArgs 2>&1 | Tee-Object -FilePath (Join-Path $CaseRoot "notes\toolrun_$stamp.txt") -Append
}

# ShellBags (UsrClass.dat + NTUSER.DAT; tool tự replay .LOG1/.LOG2 nếu có)
Run (Find-Tool "SBECmd.exe") @("-d", "$work\hives", "--csv", "$out\sbecmd\$stamp", "--dedupe")

# LNK
Run (Find-Tool "LECmd.exe")  @("-d", $recent, "--csv", "$out\lecmd\$stamp", "-q")

# Jump Lists
Run (Find-Tool "JLECmd.exe") @("-d", $recent, "--csv", "$out\jlecmd\$stamp", "-q")

# Prefetch
Run (Find-Tool "PECmd.exe")  @("-d", "$Drive\Windows\Prefetch", "--csv", "$out\pecmd\$stamp", "-q")

# Recycle Bin
Run (Find-Tool "RBCmd.exe")  @("-d", "$work\RecycleBin", "--csv", "$out\rbcmd\$stamp", "-q")

Write-Host "`nXong. Output nằm trong $out\<tool>\$stamp – mở bằng TimelineExplorer."
Write-Host "Nếu tool báo lỗi tham số, chạy '<tool>.exe -h' xem lại cú pháp của phiên bản bạn đang dùng."
