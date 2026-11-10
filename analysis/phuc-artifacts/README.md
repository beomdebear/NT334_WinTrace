# Phúc – Windows Forensic Artifact Analysis (Tuần 1 + Tuần 2)

Phân tích ShellBags, LNK, Jump Lists, Prefetch, Recycle Bin và Registry USB trên dataset **NIST CFReDS – Data Leakage Case** (PC, Windows 7, user `informant`, SID `S-1-5-21-2425377081-3129163575-2985601102-1000`).

## Evidence
- Ảnh đĩa: `cfreds_2015_data_leakage_pc.dd` – MD5 `A49D1254C873808C58E6F1BCD60B5BDE` (khớp NIST), SHA-256 `026C1436…98BE4E2`
- Nguồn: https://cfreds.nist.gov/all/NIST/DataLeakageCase – **không đưa evidence lên repo**
- Timezone máy evidence: UTC−4 (EDT) – xem `case_notes/timezone.md`. Mọi timestamp trong thư mục này là **UTC**.

## Bàn giao tuần 2 (đọc trước)

| File | Cho ai | Nội dung |
|---|---|---|
| `../../results/case01_shellbags_events.csv` | **Nam** (import), Thi, Quyên | 383 event ShellBags theo schema chung, có metadata cấu trúc: `semantic_class`, `is_user_activity`, `fs_path`, `volume`, `cross_hive_twin_ids`, `registry_write_burst`… **Đây là file duy nhất nên import vào DB** |
| `correlation_evidence_notes.md` | **Thi** | 6 tình huống kiểm thử R01–R05 (positive/negative) có event ID, 8 bẫy false correlation thật, time window đề xuất |
| `volume_map_case01.csv` | Thi, Nam | Bảng ký tự ổ/alias → thiết bị/volume theo thời gian (V: = share, E: = RM#1 rồi RM#2, D: = 3 đĩa quang) |
| `artifact_validation_week2.md` | Quyên, cả nhóm | Nguồn output nào dùng/không dùng, kiểm tra nhất quán, kiểm chứng 3 công cụ, kết quả import vào pipeline, 5 tình huống đối chiếu chéo |
| `artifact_reference_case01.md` | cả nhóm | Mục 8 mới: ngữ nghĩa timestamp ShellBags đã kiểm chứng + quy tắc dùng trong correlation |

**Vấn đề cần nhóm xử lý** (chi tiết `artifact_validation_week2.md` mục 5):
1. `src/schema.py::normalize_windows_path` làm hỏng đường dẫn UNC (`\\host\share` → `\host\share`). Test `test_unc_target_path_survives_normalization` đang đánh dấu xfail.
2. Import cả `shellbags_findings.csv` lẫn `case01_shellbags_events.csv` sẽ nhân đôi 383 event.

## Toàn bộ nội dung

| File | Nội dung |
|---|---|
| `artifact_analysis_report.md` | Báo cáo tuần 1 (đã đính chính tuần 2): evidence, tool, ShellBags, artifact bổ trợ, đối chiếu 26 hành động với NIST |
| `artifact_reference_case01.md` | Từng artifact: vị trí, ngữ nghĩa timestamp, chứng minh được / không chứng minh được |
| `candidate_findings.md` | 8 finding CASE01-F001…F008, tách observed / inferred / NIST-confirmed |
| `manual_evidence.md` | Hồ sơ kiểm chứng thủ công F001, F004, F005 (+ nhận dạng thiết bị F004, tuần 2) |
| `shellbags_findings.csv` | 383 event ShellBags theo schema mục 13.1 của đề (bản tham chiếu v2, 30 verified) |
| `artifact_validation_week2.md`, `correlation_evidence_notes.md`, `volume_map_case01.csv` | Tuần 2 (xem trên) |
| `tool_output/` | Output gốc của tool – đích của mọi tham chiếu `Lx`. SHA-256 trong `artifact_validation_week2.md` mục 8 |
| `case_notes/` | Timezone, integrity, phiên bản tool, log thu thập & lệnh, 7 ảnh kiểm chứng |

`tool_output/`: `sbecmd/Deduplicated.csv`; `lecmd/`, `jlecmd/`, `pecmd/` (**lượt chạy trên ổ mount F:**, timestamp file system đúng); `registry/registry_usb_network.csv`. Output LNK/JL/Prefetch của lượt chạy trên bản copy (`20261028_103708`) **không** được đưa lên vì sai Created/Accessed.

## Scripts

| Script | Việc |
|---|---|
| `setup_day1.ps1` | Tạo cấu trúc case, tải Eric Zimmerman Tools |
| `day2_collect.ps1 -Drive F: -User informant -CaseRoot <case>` | Copy hive (+ .LOG1/.LOG2), Prefetch, LNK, Jump Lists, Recycle Bin từ ổ mount read-only, hash SHA-256 |
| `day3_4_run_tools.ps1 -Drive F: -CaseRoot <case> -ToolDir <EZ>` | Chạy SBECmd, RBCmd trên bản copy; LECmd, JLECmd, PECmd **trực tiếp trên ổ mount** |
| `sbecmd_to_findings.py <sbecmd_csv_dir> -o shellbags_findings.csv` | SBECmd CSV → event v2, mỗi timestamp một event có `timestamp_type` |
| `to_team_schema.py` | v2 → schema chung + metadata cấu trúc (lệnh bên dưới) |
| `registry_usb_check.py <hives> -o tool_output/registry/registry_usb_network.csv` | Đọc USBSTOR, ProfileList, EMDMgmt, MountPoints2, Map Network Drive MRU bằng **python-registry** (độc lập với EZ Tools) |

Tái tạo file bàn giao chính (chạy trong `analysis/phuc-artifacts/`):
```
python scripts/to_team_schema.py shellbags_findings.csv --sbecmd-csv tool_output/sbecmd/Deduplicated.csv -o ../../results/case01_shellbags_events.csv --username informant --user-sid S-1-5-21-2425377081-3129163575-2985601102-1000
```

Kiểm thử (ở thư mục gốc repo): `python -m pytest tests/test_case01_shellbags_import.py -v`

## Ghi chú
- Ảnh và ghi chú lưu ở `case_notes/` (không dùng tên `evidence/` vì `.gitignore` của nhóm chặn mọi thư mục `evidence/`).
- Ba mức kết luận: **Observed** · **Inferred** · **NIST-confirmed**; "Verified (GUI)" = kiểm chứng bằng ShellBags Explorer; tuần 2 thêm python-registry làm công cụ thứ ba.
- Kết quả: 3 finding verified bằng công cụ độc lập (F001, F004, F005); 19/26 hành động NIST có artifact khớp (tuần 1), ◐ thêm 1 nhờ Registry USB (tuần 2).
