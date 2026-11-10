# Correlation Evidence Notes – CASE01 (Phúc → Thi)

Mục đích: cung cấp cho correlation engine (R01–R05) các tình huống CASE01 **có đủ bằng chứng**, kèm event ID, các trường nên dùng, và các bẫy false correlation đã gặp trên dữ liệu thật.
Chi tiết bằng chứng: `artifact_validation_week2.md` mục 6. Bảng alias ổ đĩa: `volume_map_case01.csv`.

Đầu vào ShellBags cho engine: `results/case01_shellbags_events.csv` (383 event, schema chung). **Không** nạp thêm `shellbags_findings.csv` (trùng 383 event).

---

## 1. Các trường mới trong `extra_attributes` của ShellBags

| Trường | Giá trị | Dùng cho |
|---|---|---|
| `semantic_class` | `user_interaction` (152) · `registry_write_unattributed` (63) · `target_metadata` (168) | **Lọc trước khi áp dụng time window**: chỉ `user_interaction` mới là hành động người dùng |
| `is_user_activity` | `true` / `false` | Dạng boolean của dòng trên |
| `timestamp_type` | `ShellBag_FirstInteracted`, `ShellBag_LastInteracted`, `ShellBag_KeyLastWrite`, `ShellItem_Folder{Created,Modified,Accessed}` | Không gộp các loại này với nhau |
| `timestamp_precision` | `registry_100ns` · `fat_2s` · `fat_date_only` | Không so khớp mốc `fat_date_only` theo giờ |
| `fs_path` | `E:\...`, `\\10.11.11.128\secured_drive\...`, `C:\Users\informant\...` hoặc rỗng (mục ảo) | **R02 Object Association** (so với path của LNK/Jump List/Prefetch) |
| `fs_path_basis` | `drive_letter` · `unc` · `user_profile_inferred` · `virtual` | `user_profile_inferred` là ánh xạ suy luận (Desktop namespace → `C:\Users\informant\Desktop`) |
| `volume` | `E:`, `D:`, `\\10.11.11.128\secured_drive`… | Kết hợp `volume_map_case01.csv` để biết **thiết bị** theo thời gian |
| `inside_archive`, `archive_path` | duyệt bên trong file `.zip` | Đối tượng thật là file zip, không phải thư mục |
| `cdburn_staging` | `true` cho shell type CDBurn | Khu chờ ghi đĩa, chưa chắc đã ghi |
| `cross_hive_twin_ids` | event ID ở hive kia, cùng thư mục, lệch ≤ 60 s | **Không đếm là 2 bằng chứng độc lập** |
| `registry_write_burst` | số event KeyLastWrite cùng hive cùng mốc | Burst lớn = một lần ghi registry |
| `mru_position`, `bag_path`, `slot`, `node_slot`, `shell_type`, `hive`, `source_line` | metadata gốc | Hiển thị evidence detail, truy ngược |

> Lưu ý pipeline: hiện tại `target_path` dạng UNC bị `normalize_windows_path` đổi `\\host` thành `\host` (đã báo Nam). Trong khi chờ sửa, R02 nên so trên `extra_attributes.fs_path` (không bị normalize).

## 2. Tình huống đề xuất cho kiểm thử correlation

Mỗi tình huống có **kỳ vọng**: nên liên kết (positive) hoặc **không** nên kết luận (negative).

### C1 – Duyệt share rồi mở file bằng Excel (R01, R02, R03) · Positive

| Vai trò | Nguồn | Tham chiếu | UTC |
|---|---|---|---|
| Duyệt thư mục | ShellBags | `CASE01-SB0133` (UsrClass, pricing decision, First) · `CASE01-SB0158` (MRU0, Last) | 20:24:15 · 20:28:17 |
| Mở file | Jump List – Excel 12 | `AutomaticDestinations_fromF.csv` L23, `\\10.11.11.128\secured_drive\Secret Project Data\pricing decision\(secret_project)_pricing_decision.xlsx` | 20:26:53 |
| Mở file | LNK | `LECmd_Output_fromF.csv` L2 | 20:26:53 |
| Gắn ổ mạng | Registry | `registry_usb_network.csv`: Map Network Drive MRU, MountPoints2 | 20:26:04 |

- Khớp R02: `fs_path` của SB0133 là thư mục cha của file trong JL L23.
- Kết luận được phép: "file pricing_decision.xlsx trên share được mở bằng Excel sau khi user duyệt thư mục chứa nó".
- **Không** được kết luận: file đã bị sao chép (không artifact nào trong bộ này chứng minh).

### C2 – Cùng file, hai đường dẫn: V: và UNC (R02 với alias) · Positive

| Nguồn | Tham chiếu | Path | UTC |
|---|---|---|---|
| Jump List | L21 | `V:\Secret Project Data\final\[secret_project]_final_meeting.pptx` | 20:27:33 |
| LNK | L15 | `\\10.11.11.128\secured_drive\...\final_meeting.pptx` | 20:27:33 |
| ShellBags | `CASE01-SB0147`/`SB0148` `V:\Secret Project Data\final` | | 20:27:29 |

- Nếu không dùng bảng alias, R02 sẽ coi đây là **2 đối tượng khác nhau** (false negative).
- Alias hợp lệ trong khoảng `2015-03-23T20:26:04Z` – `20:29:00Z` (`volume_map_case01.csv`).

### C3 – Cùng tên file trên hai thiết bị khác nhau (R02 phải phân biệt volume) · Negative cho "cùng đối tượng"

| Nguồn | Tham chiếu | Path | Volume serial | UTC |
|---|---|---|---|---|
| ShellBags | `CASE01-SB0266` | `E:\Secret Project Data\design\winter_whether_advisory.zip` | (RM#2) | 14:01:29 |
| Jump List | L9 | cùng path trên E: | `9E6A5B82` | 14:01:23 |
| Jump List | L7 | `D:\de\winter_whether_advisory.zip` | `E297F1A5` (CD) | 20:44:13 |
| LNK | L13 | **một LNK duy nhất**: Created 14:01:23 (E:), Modified 20:44:18 → `D:\de\...` | `E297F1A5` | |

- Kỳ vọng: hai **bản** file trên hai volume khác nhau. Có thể kết luận "file đi từ USB RM#2 sang CD" (inferred), nhưng **không** gán Created của LNK (14:01:23) cho path `D:\de\...`. LNK chỉ giữ path của lần mở cuối.

### C4 – Hai USB cùng ký tự E: (R02/R03 phải dùng thiết bị, không dùng ký tự ổ) · Negative cho "cùng thiết bị"

| Sự kiện | Tham chiếu | Thiết bị (theo `volume_map_case01.csv`) |
|---|---|---|
| `E:\RM#1\Secret Project Data` | `CASE01-SB0172` 2015-03-24 13:38:31 | RM#1 (VSN `5C754D3E`) |
| `E:\Secret Project Data` | `CASE01-SB0260` 2015-03-24 14:00:19 | RM#2 (VSN `9E6A5B82`) |

- Hai sự kiện cách nhau 22 phút, cùng `E:`, cùng tên thư mục con, nhưng **khác thiết bị**.

### C5 – Chương trình chạy và file nó xử lý (R04) · Positive và Negative

| Kỳ vọng | Chương trình | Bằng chứng | Kết luận được phép |
|---|---|---|---|
| **Positive** | `WINWORD.EXE` (PF L88, last 2015-03-25 15:24:48) | `FilesLoaded` chứa `RESIGNATION_LETTER_(IAMAN_INFORMANT).DOCX`; LNK L9; JL L19 | Word đã nạp file này |
| **Positive** | `XPSRCHVW.EXE` (PF L96, 15:28:47) | `FilesLoaded` chứa `.XPS`; LNK L10; JL L32 | XPS Viewer đã mở file `.xps` |
| **Negative** | `IEXPLORE.EXE` (14 lần chạy) | `FilesLoaded` cũng chứa `RESIGNATION_LETTER...DOCX` | **Không** kết luận IE "mở" file: có thể do hộp thoại chọn file hoặc tải lên |
| **Negative** | `ERASER.EXE` (PF L26, last 15:13:30) | `Directories` có `...\DESKTOP`, không có file cụ thể; ShellBag `Desktop\temp` (`SB0298`) chỉ cho biết thư mục từng tồn tại | **Không** kết luận Eraser đã xóa `Desktop\temp` từ artifact (NIST mới xác nhận điều đó) |
| **Negative** | Excel/PowerPoint | Có JL/LNK mở file nhưng **không có** `.pf` | Không xác nhận thực thi bằng Prefetch; dùng Jump List AppID làm bằng chứng mở file |

### C6 – Ngữ cảnh xóa (R05) · Chỉ được ở mức "ngữ cảnh"

| Thời điểm (25/03) | Nguồn | Tham chiếu |
|---|---|---|
| 14:14:17 | ShellBags Recycle Bin | `CASE01-SB0346` |
| 14:50:14 – 15:15:50 | Prefetch Eraser / CCleaner | PF L25, L26, L8, L7 |
| 15:18:29 – 15:19:20 | Prefetch UNINST/MSIEXEC + ShellBags Programs and Features | PF L81, L42, L43 · `CASE01-SB0354`–`SB0356` |
| (thời điểm thu thập) | Recycle Bin trống | RBCmd 0 file |

- Kết luận được phép: "có hoạt động cài/chạy công cụ xóa dữ liệu và gỡ phần mềm trong khoảng 14:50–15:20Z".
- **Không** có `$I` nên không có "Deletion Timestamp" nào. R05 không được tạo sự kiện xóa giả định.

## 3. Bẫy false correlation đã gặp trên dữ liệu thật

| # | Bẫy | Ví dụ CASE01 | Cách tránh |
|---|---|---|---|
| F1 | Cùng một lần duyệt ghi ở **2 hive** | `SB0131` (UsrClass 20:24:12) và `SB0132` (NTUSER 20:24:14); lệch tới 33 s (`SB0115`/`SB0119`) | Gộp theo `cross_hive_twin_ids`; tính là **1** bằng chứng |
| F2 | **Jump List Explorer** và **ShellBags** cùng do Explorer ghi | JL L8 `...zip\ppt` 14:01:29 vs `SB0266` 14:01:29 | R03 không coi cặp này là 2 nguồn độc lập; LNK, Prefetch, Registry USB mới là nguồn khác cơ chế |
| F3 | **Burst** registry | 13 event lúc 2015-03-25T15:30:06Z; 9 event lúc 13:57:40Z | Bỏ `registry_write_unattributed`; với burst > 1 chỉ giữ mục MRU0 |
| F4 | **Metadata** đứng chung timeline với hành động | `SB0001` 2014-12-16 (Modified của zip) | Chỉ áp dụng R01 cho `is_user_activity=true` |
| F5 | **Ký tự ổ** tái sử dụng | C4 | Dùng `volume_map_case01.csv` |
| F6 | **Một LNK, nhiều vị trí** | C3 | Không gán `SourceCreated` của LNK cho path hiện tại |
| F7 | **Có tên file trong Prefetch ≠ chương trình mở file** | `IEXPLORE.EXE` (C5) | R04 cần thêm JL AppID hoặc LNK cùng thời điểm |
| F8 | **Mốc ground truth có thể lệch artifact** | `D:\de` có từ 19:54:35Z, NIST ghi đổi tên lúc 20:40Z | Ghi nhận "mâu thuẫn", không ép khớp |

## 4. Time window đề xuất (đo trên CASE01)

| Quan hệ | Khoảng lệch quan sát | Window đề xuất |
|---|---|---|
| Cùng thư mục, 2 hive (twin) | 0–33 s | ≤ 60 s, và **gộp**, không cộng điểm |
| ShellBag ↔ Jump List Explorer, cùng mục | 0–6 s | ≤ 10 s (cùng cơ chế) |
| ShellBag ↔ LNK, cùng file/thư mục | 6 s (`SB0266` 14:01:29 vs LNK Created 14:01:23) | ≤ 60 s |
| Gắn ổ mạng (Registry) ↔ duyệt share (ShellBags) | MountPoints2 20:26:04 nằm giữa phiên 20:23:28–20:28:17 | cùng phiên (≤ 5 phút) |
| USBSTOR first install ↔ EMDMgmt | 1 s | ≤ 5 s để liên kết thiết bị–volume |
| Prefetch LastRun ↔ LNK cùng file | WINWORD 15:24:48 vs LNK 15:29:08 (4 phút 20 s) | ≤ 10 phút, và phải có `FilesLoaded` hoặc JL AppID |

## 5. Những gì artifact của Phúc KHÔNG cung cấp

- Thời điểm **sao chép, đổi tên, xóa** file: cần `$MFT` / `$UsnJrnl` (đề xuất tuần 3).
- Ai cắm USB: chỉ có SID của user sở hữu hive NTUSER/UsrClass (`informant`, `S-1-5-21-2425377081-3129163575-2985601102-1000`); USBSTOR là cấp máy.
- Nội dung file trong zip/CD: ShellBags chỉ cho thấy đã duyệt bên trong (`ppt`, `slides`, `slideMasters`).
