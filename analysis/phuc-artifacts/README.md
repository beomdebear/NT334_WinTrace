# Phúc – Windows Forensic Artifact Analysis (Tuần 1)

Phân tích ShellBags, LNK, Jump Lists, Prefetch, Recycle Bin trên dataset **NIST CFReDS – Data Leakage Case** (PC, Windows 7, user `informant`).

## Evidence
- Ảnh đĩa: `cfreds_2015_data_leakage_pc.dd` – MD5 `A49D1254C873808C58E6F1BCD60B5BDE` (khớp NIST), SHA-256 `026C1436…98BE4E2`
- Nguồn: https://cfreds.nist.gov/all/NIST/DataLeakageCase – **không đưa evidence lên repo**
- Timezone máy evidence: UTC−4 (EDT) – xem `evidence/timezone.md`. Mọi timestamp trong thư mục này là **UTC**.

## Nội dung

| File | Nội dung |
|---|---|
| `artifact_analysis_report.md` | Báo cáo tuần 1: evidence, tool, ShellBags, artifact bổ trợ, **đối chiếu 26 hành động với đáp án NIST**, findings, hạn chế, đề xuất tuần 2 |
| `artifact_reference_case01.md` | Từng artifact: vị trí, ngữ nghĩa timestamp, chứng minh được / không chứng minh được, quan sát thực tế trên CASE01 (bổ sung cho `docs/artifact_reference.md` – phần lý thuyết chung) |
| `candidate_findings.md` | 8 finding CASE01-F001…F008, tách observed / inferred, chuỗi sự kiện sơ bộ |
| `manual_evidence.md` | Hồ sơ kiểm chứng thủ công (ShellBags Explorer) cho F001, F004, F005 |
| `shellbags_findings.csv` | 383 event ShellBags theo schema mục 13.1 của đề (30 verified) |
| `../../results/case01_shellbags_events.csv` | Cùng 383 event, theo **schema chung của nhóm** (`docs/event_schema.md`) – đã kiểm hợp lệ với `src/schema.py::ForensicEvent` |
| `scripts/` | Script thu thập và chuyển đổi (xem dưới) |
| `evidence/` | Timezone, phiên bản tool |

## Scripts

| Script | Việc |
|---|---|
| `setup_day1.ps1` | Tạo cấu trúc case, tải Eric Zimmerman Tools |
| `day2_collect.ps1 -Drive F: -User informant -CaseRoot <case>` | Copy hive (+ .LOG1/.LOG2), Prefetch, LNK, Jump Lists, Recycle Bin từ ổ mount read-only, hash SHA-256 |
| `day3_4_run_tools.ps1 -Drive F: -CaseRoot <case> -ToolDir <EZ>` | Chạy SBECmd, RBCmd trên bản copy; LECmd, JLECmd, PECmd **trực tiếp trên ổ mount** (giữ timestamp file system) |
| `sbecmd_to_findings.py <sbecmd_csv_dir> -o shellbags_findings.csv` | SBECmd CSV → event, mỗi timestamp một event có `timestamp_type` |
| `to_team_schema.py shellbags_findings.csv -o case01_shellbags_events.csv --username informant` | Chuyển sang schema chung của nhóm, giữ `event_id` và `validation_status` |

## Ghi chú
- Đường dẫn `notes/...`, `output/...` trong các báo cáo là thư mục case cục bộ (không nằm trong repo). Ảnh kiểm chứng sẽ được bổ sung vào `evidence/img/`.
- Kết quả tuần 1: 3 finding verified bằng GUI độc lập (F001, F004, F005); 19/26 hành động trong đáp án NIST có artifact khớp.
