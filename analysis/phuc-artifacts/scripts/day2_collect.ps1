# Ngày 2 – Lấy artifact từ image đã mount (READ ONLY) sang evidence_work + hash
# Trước khi chạy: FTK Imager → File → Image Mounting → chọn .dd → Mount Method: Block Device / Read Only
# Ghi lại ký tự ổ được gán (ví dụ F:)
# Chạy: .\day2_collect.ps1 -Drive F: -User informant

param(
    [Parameter(Mandatory=$true)][string]$Drive,
    [string]$User = "informant",
    [string]$CaseRoot = "C:\case01"
)

$ErrorActionPreference = "Continue"
$Drive = $Drive.TrimEnd('\')
$work  = Join-Path $CaseRoot "evidence_work"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$log   = Join-Path $CaseRoot "notes\collection_log.md"

function Log($m) { "$((Get-Date).ToUniversalTime().ToString('u')) | $m" | Tee-Object -FilePath $log -Append }

if (-not (Test-Path "$Drive\Windows")) { Write-Error "Không thấy $Drive\Windows – kiểm tra lại ổ mount (có thể là phân vùng khác)."; exit 1 }
if (-not (Test-Path "$Drive\Users\$User")) {
    Write-Warning "Không thấy user '$User'. Các user có trong image:"
    Get-ChildItem "$Drive\Users" -Directory | Select-Object -ExpandProperty Name
    exit 1
}

Log "Bắt đầu thu thập từ $Drive (user: $User)"

function Copy-Artifact($src, $dst) {
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force -ErrorAction Continue
        Log "Copied: $src -> $dst"
    } else { Log "KHÔNG TỒN TẠI: $src" }
}

# Hives + transaction logs
$h = Join-Path $work "hives"
$ud = "$Drive\Users\$User"
foreach ($f in "NTUSER.DAT","NTUSER.DAT.LOG","NTUSER.DAT.LOG1","NTUSER.DAT.LOG2") { Copy-Artifact "$ud\$f" $h }
$uc = "$ud\AppData\Local\Microsoft\Windows"
foreach ($f in "UsrClass.dat","UsrClass.dat.LOG","UsrClass.dat.LOG1","UsrClass.dat.LOG2") { Copy-Artifact "$uc\$f" $h }
foreach ($f in "SYSTEM","SOFTWARE","SAM") {
    foreach ($ext in "",".LOG",".LOG1",".LOG2") { Copy-Artifact "$Drive\Windows\System32\config\$f$ext" $h }
}

# Prefetch
Copy-Artifact "$Drive\Windows\Prefetch\*.pf" (Join-Path $work "Prefetch")

# LNK (Recent) + Jump Lists
Copy-Artifact "$ud\AppData\Roaming\Microsoft\Windows\Recent\*.lnk" (Join-Path $work "Recent")
Copy-Artifact "$ud\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*" (Join-Path $work "JumpLists")
Copy-Artifact "$ud\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*" (Join-Path $work "JumpLists")

# Recycle Bin (giữ cấu trúc thư mục SID)
if (Test-Path "$Drive\`$Recycle.Bin") {
    Copy-Item -Path "$Drive\`$Recycle.Bin\*" -Destination (Join-Path $work "RecycleBin") -Recurse -Force -ErrorAction Continue
    Log "Copied: $Drive\`$Recycle.Bin -> RecycleBin"
} else { Log "KHÔNG TỒN TẠI: $Drive\`$Recycle.Bin" }

# Hash toàn bộ evidence_work
$out = Join-Path $CaseRoot "notes\hashes_evidence_work_$stamp.csv"
Get-ChildItem $work -Recurse -File -Force |
    Get-FileHash -Algorithm SHA256 |
    Select-Object Hash, Path |
    Export-Csv $out -NoTypeInformation -Encoding utf8
Log "Đã hash evidence_work -> $out"

# Timezone của máy evidence (để đối chiếu UTC)
Log "Nhắc: mở SYSTEM hive bằng Registry Explorer, xem ControlSet00x\Control\TimeZoneInformation và ghi vào notes."
Write-Host "`nXong. Kiểm tra $log để xem file nào thiếu."
