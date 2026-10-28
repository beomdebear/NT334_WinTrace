# Artifact Analysis Report – Tuần 1 – CASE01

**Dự án:** WinTrace – Automated Windows Forensic Artifact Extraction & Super Timeline Analysis
**Người thực hiện:** Phúc – Windows Forensic Artifact Analyst
**Ngày:** 2026-10-28
**Trạng thái:** Hoàn thành tuần 1 (mục 5 – đối chiếu Plaso – chờ CSV của Nam)

> **Ba mức kết luận dùng trong báo cáo:**
> - **Observed** – artifact cho thấy trực tiếp (có tham chiếu file/dòng).
> - **Inferred** – suy luận từ artifact, chưa có bằng chứng trực tiếp.
> - **NIST-confirmed** – suy luận/quan sát khớp với đáp án chính thức của NIST (ground truth). Đây là kiểm chứng *bên ngoài*, khác với kiểm chứng bằng công cụ độc lập (ShellBags Explorer).

> Quy ước giờ: mọi timestamp ở **UTC** (hậu tố Z). Giờ máy nghi phạm = UTC − 4h (EDT).
> Đáp án NIST ghi theo giờ EDT, được quy về UTC (+4h) trước khi so sánh.

---

## 1. Evidence

| Mục | Giá trị |
|---|---|
| Nguồn | NIST CFReDS – Data Leakage Case (2015), ảnh đĩa máy PC, Windows 7 |
| File tải | `cfreds_2015_data_leakage_pc.7z.001/.002/.003` – MD5 khớp giá trị công bố (`c327db25…`, `8a518514…`, `e155d374…`) |
| Ảnh đĩa | `cfreds_2015_data_leakage_pc.dd` (~20 GB) |
| MD5 ảnh đĩa | `A49D1254C873808C58E6F1BCD60B5BDE` – **khớp** NIST (leakage-answers.pdf, mục 4.1) |
| SHA-256 ảnh đĩa | `026C143638295DB1FBFA598C5B35BCAC4860BA73EC5DA1CC87B67AFD598BE4E2` |
| Mount | FTK Imager, Block Device / **Read Only**; phân vùng hệ thống → F:, System Reserved → E: |
| User phân tích | `informant` |
| Timezone máy evidence | Eastern Standard Time; Bias 300; ActiveTimeBias 240 ⇒ UTC−4 (EDT) trong giai đoạn sự kiện (DST 2015 bắt đầu 08/03) |
| Bằng chứng timezone | SYSTEM `Select\Current`=1 → `ControlSet001\Control\TimeZoneInformation` (ảnh `case_notes/img/select_current.png`, `case_notes/img/timezone.png`) |

**Thu thập artifact:** script `day2_collect.ps1` copy từ F: sang `evidence_work/` (hive + .LOG1/.LOG2, Prefetch, LNK, Jump Lists, Recycle Bin) và hash SHA-256 toàn bộ. Hai lượt thu thập cho hash giống hệt ⇒ quy trình ổn định, không làm thay đổi evidence. Log: `case_notes/collection_log.md`; hash: `case_notes/integrity.md`.

## 2. Công cụ và phiên bản

| Tool | Phiên bản | Dùng cho |
|---|---|---|
| SBECmd | 2026.10.2 | Trích xuất ShellBags |
| ShellBags Explorer | 2026.10.1 | **Kiểm chứng độc lập** ShellBags |
| Registry Explorer | 2026.10.1 | Đọc SYSTEM hive (timezone) |
| LECmd | 2026.10.3 | LNK |
| JLECmd | 2026.10.5 | Jump Lists |
| PECmd | 2026.10.3 | Prefetch |
| RBCmd | 2026.10.1 | Recycle Bin |
| Timeline Explorer | 2026.10.0 | Xem CSV |
| FTK Imager | 8.3.0.27 | Mount ảnh đĩa read-only |
| `sbecmd_to_findings.py` | tự viết | Chuyển output SBECmd → schema nhóm |

Toàn bộ lệnh chạy được ghi trong `case_notes/command_log.md`.

## 3. ShellBags

### 3.1. Vị trí và cấu trúc
- Nguồn chính: `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`; nguồn phụ: `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`.
- BagMRU là cây phản chiếu cây thư mục; mỗi value số là một shell item; `MRUListEx` cho thứ tự gần nhất; `NodeSlot` trỏ sang `Bags`.
- Chi tiết: `artifact_reference_case01.md` mục 1.

### 3.2. Ngữ nghĩa timestamp
- **Key LastWrite** chỉ gắn chắc với mục **MRU 0**. Ví dụ: trong `Secret Project Data` trên share, `pricing decision` (MRU 0) có Last interacted = LastWrite = 20:28:17Z, còn `design` (MRU 5) chỉ có First interacted 20:24:12Z đáng tin.
- **Target Created/Modified/Accessed** trong shell item là MAC của thư mục/file đích, **không phải** thời điểm truy cập.
- Độ phân giải: shell item dùng FAT time (2 giây); hai hive ghi cùng thư mục lệch ~2 giây.

### 3.3. Kết quả trích xuất
- **109 ShellBag** duy nhất từ 2 hive (SBECmd, 0 trùng) → **383 event** trong `shellbags_findings.csv` (mỗi timestamp một event, có `timestamp_type`).
- **Không mất tham chiếu:** cả 109/109 dòng SBECmd đều được trỏ tới từ `evidence_reference`. 5 ShellBag có mốc trùng hệt một ShellBag khác cùng BagPath (ổ D: và 4 thư viện) không tạo event riêng mà được ghép vào event sẵn có dưới dạng `also=Deduplicated.csv:L<n>`. Output gốc của SBECmd lưu tại `tool_output/sbecmd/Deduplicated.csv` (SHA-256 trong `case_notes/integrity.md`).
- Phân bố `timestamp_type`: KeyLastWrite 104, FirstInteracted 70, FolderCreated/Modified/Accessed 56 mỗi loại, LastInteracted 41.
- Nhóm thư mục đáng chú ý:

| Nhóm | Ví dụ path | Ý nghĩa |
|---|---|---|
| Network share | `\\10.11.11.128\secured_drive\Secret Project Data\{design, final, pricing decision, progress, proposal, technical review}` | Nguồn dữ liệu mật |
| Ổ mạng ánh xạ | `V:\Secret Project Data\final` | Cùng share (xác nhận qua Jump List) |
| Desktop | `Desktop\S data\Secret Project Data\...` | Nơi tập kết dữ liệu (đã bị xóa nhưng ShellBags còn) |
| Ổ ngoài E: | `E:\RM#1\Secret Project Data`, `E:\Secret Project Data\...` | USB RM#1 và RM#2 |
| Ổ quang D: (CDBurn) | `D:\de`, `D:\pd`, `D:\prog`, `D:\prop`, `D:\tr` | Khu chờ ghi CD, tên viết tắt |
| Cloud | `Users Files\Google Drive` | Kênh rò rỉ qua cloud |
| Anti-forensics | `Desktop\temp`, `Recycle Bin`, `Programs and Features` | Thư mục bị Eraser xóa, xem thùng rác, gỡ phần mềm |

### 3.4. Kiểm chứng: SBECmd vs ShellBags Explorer

| Finding | Hive | Mục | SBECmd | ShellBags Explorer | Kết quả |
|---|---|---|---|---|---|
| F001 | UsrClass | `secured_drive\...\design` – First interacted | 2015-03-23 20:24:12 | 20:24:12.943 | Khớp |
| F001 | UsrClass | `secured_drive\...\pricing decision` – Last interacted (MRU 0) | 20:28:17 | 20:28:17.754 | Khớp |
| F001 | NTUSER | `secured_drive\...\design` – First interacted | 20:24:14 | 20:24:14.753 | Khớp |
| F004 | UsrClass | `E:\...\winter_whether_advisory.zip` – Last interacted | 2015-03-24 14:01:29 | 14:01:29.766 | Khớp |
| F004 | UsrClass | `...zip\ppt` – First/Last | 14:01:32 | 14:01:32 | Khớp |
| F005 | UsrClass | `D:\de` (CDBurn) – First / Last | 19:54:35 / 20:44:13 | 19:54:35.357 / 20:44:13.155 | Khớp |

**Kết quả:** 6/6 mục kiểm tra khớp đến giây, cùng MRU position, cùng shell type, cùng key path. 30 event trong `shellbags_findings.csv` được đổi sang `verified`. Chênh lệch duy nhất: SBECmd làm tròn xuống giây, GUI hiển thị mili giây.

### 3.5. Giới hạn suy luận từ ShellBags
1. Chỉ chứng minh thư mục được **hiển thị/tương tác** qua Explorer – không chứng minh file nào được mở/sao chép.
2. Chỉ ghi **ký tự ổ**, không ghi thiết bị: E: lúc 13:38Z là RM#1 nhưng lúc 13:58Z+ là RM#2 (ngày 24/03).
3. Chỉ có lần tương tác đầu/cuối, không có các lần ở giữa.
4. Timestamp có thể lệch so với hành vi thật: `D:\de` First interacted 19:54:35Z (15:54 EDT) trong khi NIST ghi đổi tên thành `de` lúc 16:40 EDT. NIST cũng lưu ý timestamp ShellBag/JumpList có thể không chính xác.

## 4. Artifact bổ trợ

### 4.1. LNK / Jump Lists
- 15 LNK, 31 entry AutomaticDestinations (14 file Jump List).
- Bằng chứng mở file từ share (Excel mở `(secret_project)_pricing_decision.xlsx` 20:26:53Z), từ E:\RM#1 (`[secret_project]_proposal.docx` 18:37:20Z, `[secret_project]_design_concept.ppt` 18:38:21Z ngày 23/03), từ CD (`D:\de\winter_whether_advisory.zip` 20:44:18Z ngày 24/03).
- `winter_whether_advisory.zip.lnk`: Created 14:01:23Z (mở trên E:), Modified 20:44:18Z (mở từ D:\de) ⇒ một LNK ghi nhận file đi qua 2 thiết bị.
- Jump List `V:\...\final_meeting.pptx` + LNK cùng file trỏ `\\10.11.11.128\secured_drive` ⇒ V: là ổ mạng ánh xạ.

### 4.2. Prefetch
- 95 file .pf. Ngày 25/03: Eraser (cài 14:50Z, chạy 15:13:30Z), CCleaner (cài 14:57:56Z, chạy 15:15:50Z), UNINST.EXE 15:18:29Z, Google Drive 15:21:31Z, Word 15:24:48Z, XPS Viewer 15:28:47Z.

### 4.3. Recycle Bin
- 3 thư mục SID, 0 file `$I` ⇒ thùng rác trống tại thời điểm thu thập. NIST xác nhận user đã Empty Recycle Bin (15:14Z 25/03) và dùng Shift+Delete.

## 5. Đối chiếu timestamp với Plaso

| Sự kiện | EZ Tools (UTC) | Plaso (UTC) | Lệch | Ghi chú |
|---|---|---|---|---|
| ShellBag `secured_drive\...\pricing decision` | 2015-03-23 20:28:17 | _chờ CSV của Nam_ | | |
| LNK `winter_whether_advisory.zip.lnk` Created | 2015-03-24 14:01:23 | | | |
| Prefetch ERASER.EXE LastRun | 2015-03-25 15:13:30 | | | |

> Yêu cầu Nam chạy Plaso trên **file .dd**, không chạy trên `evidence_work/` (bản copy đã mất Created/Accessed của LNK và .pf).

## 6. Đối chiếu với đáp án NIST (ground truth)

Đơn vị đánh giá: **một hành động** trong timeline kịch bản của NIST (ngày 23–25/03). ✅ = có artifact khớp thời gian (≤ ~1 phút) và đối tượng; ◐ = có dấu vết liên quan nhưng không trực tiếp/lệch thời gian; ✗ = artifact của phần Phúc không ghi nhận.

| NIST (EDT) | UTC | Hành động | Artifact của Phúc | Kết quả |
|---|---|---|---|---|
| 23/03 14:37–14:39 | 18:37–18:39Z | Mở file trên USB RM#1 | LNK `E:\RM#1\...proposal.docx` 18:37:20Z, `...design_concept.ppt` 18:38:21Z; Jump List | ✅ |
| 23/03 16:23 | 20:23Z | Kết nối `\\10.11.11.128\secured_drive` | ShellBag `10.11.11.128` 20:23:28Z (UsrClass) – khớp đến giây với RunMRU 16:23:28 EDT | ✅ |
| 23/03 16:24 | 20:24Z | Duyệt thư mục trên share | ShellBags 20:24:01–20:24:35Z (2 hive) | ✅ (F001 verified) |
| 23/03 16:26 | 20:26Z | Map V: tới share | ShellBag `V:\Secret Project Data` 20:27:24Z; Jump List V: | ✅ |
| 23/03 16:28 | 20:28Z | Copy pricing_decision.xlsx, final_meeting.pptx về `S data` | LNK/Jump List mở 2 file 20:26:53Z, 20:27:33Z; LastWrite share 20:28:17Z | ◐ (thấy mở, không thấy copy) |
| 23/03 16:30–16:31 | 20:30–20:31Z | Đổi tên file thành happy_holiday.jpg… | – | ✗ (cần $UsnJrnl) |
| 24/03 09:38 | 13:38Z | Cắm lại RM#1 | ShellBag `E:\RM#1\Secret Project Data` 13:38:31Z | ✅ |
| 24/03 09:40 | 13:40Z | Copy từ RM#1 vào `S data\Secret Project Data` | ShellBag `Desktop\S data\Secret Project Data` 13:40:13Z | ✅ |
| 24/03 09:47 | 13:47Z | Copy 20 file từ share vào `S data` | ShellBag share LastWrite 13:47:54Z; `S data\...\Common Data` 13:47:59Z | ✅ |
| 24/03 09:50–09:56 | 13:50–13:56Z | Đổi tên 20 file | ShellBags các thư mục con `S data\...` 13:50:50–13:57:40Z | ◐ (thấy duyệt, không thấy đổi tên) |
| 24/03 09:58–09:59 | 13:58–13:59Z | Cắm RM#2, copy toàn bộ sang RM#2 | Target Created của zip trên E: = 13:59:38Z | ✅ (F004 verified) |
| 24/03 10:00–10:01 | 14:00–14:01Z | Mở `winter_whether_advisory.zip` trên RM#2 | LNK 14:01:23Z, ShellBag 14:01:29Z – khớp đến giây với NIST | ✅ (F004 verified) |
| 24/03 10:07 | 14:07Z | Xóa `S data` (Shift+Delete) | ShellBags vẫn còn thư mục, không có thời điểm xóa | ✗ |
| 24/03 15:40–16:35 | 19:40–20:35Z | Tập ghi CD với file trong `Desktop\temp` | ShellBag `Desktop\temp` 19:52:13Z; `D:\de` (CDBurn) 19:54:35Z | ◐ |
| 24/03 16:40–16:41 | 20:40–20:41Z | Đổi tên thư mục thành de/pd/prog/prop/tr, ghi CD-R | ShellBags CDBurn `pd` 20:44:10Z, `prog`/`prop` 20:44:11Z | ✅ (F005 verified) |
| 24/03 16:44 | 20:44Z | Kiểm tra nội dung CD | LNK zip `D:\de` 20:44:18Z; ShellBag `...zip\ppt\slideMasters` 20:44:18Z | ✅ |
| 24/03 16:57–17:01 | 20:57–21:01Z | Copy ảnh Koala/Penguins/Tulips, kiểm tra CD | LNK 3 ảnh trên D: (serial AE88F176) 21:01:10–14Z | ✅ |
| 24/03 17:02 | 21:02Z | Quick-format RM#2 | – | ✗ |
| 25/03 10:50 | 14:50Z | Cài Eraser, CCleaner | Prefetch installer 14:50:14Z, 14:57:56Z | ✅ |
| 25/03 11:13 | 15:13Z | Eraser xóa `Desktop\temp` | Prefetch ERASER.EXE 15:13:30Z; ShellBag `Desktop\temp` tồn tại | ✅ |
| 25/03 11:14 | 15:14Z | Empty Recycle Bin | Recycle Bin trống (RBCmd 0 file) – chỉ là vắng mặt dấu vết | ◐ |
| 25/03 11:15 | 15:15Z | Mở CCleaner (không làm gì) | Prefetch CCLEANER64 15:15:50Z | ✅ |
| 25/03 11:18 | 15:18Z | Gỡ CCleaner và iCloud | Prefetch UNINST.EXE 15:18:29Z; ShellBag Programs and Features 15:19:20Z | ✅ |
| 25/03 11:22 | 15:22Z | Mở Google Drive, ngắt tài khoản | Prefetch GOOGLEDRIVESYNC 15:21:31Z; ShellBag Google Drive 15:20:59Z | ✅ |
| 25/03 11:24 | 15:24Z | Mở thư xin nghỉ việc (.docx) | Prefetch WINWORD 15:24:48Z; LNK docx 15:29:08Z | ✅ |
| 25/03 11:28 | 15:28Z | In ra XPS và xem | LNK .xps 15:28:33Z; Prefetch XPSRCHVW 15:28:47Z | ✅ |

**Tổng hợp:** 26 hành động – ✅ 19, ◐ 4, ✗ 3. Các hành động ✗ (đổi tên file, xóa thư mục, format USB) là hành vi trên **file system**, nằm ngoài phạm vi ShellBags/LNK/Prefetch ⇒ cần $MFT/$UsnJrnl (đề xuất tuần 2).

> Đây là đối chiếu trên các mốc NIST liệt kê, **không phải** precision/recall: NIST không liệt kê mọi hành vi, và một hành động có thể có nhiều artifact.

## 7. Danh sách findings

| ID | Mô tả | Artifact | Thời gian (UTC) | Confidence | Validation |
|---|---|---|---|---|---|
| CASE01-F001 | Duyệt `Secret Project Data` trên `\\10.11.11.128\secured_drive` | ShellBags (2 hive), LNK, Jump List | 2015-03-23 20:23:28–20:28:17 | High | **Verified (GUI)** + NIST-confirmed |
| CASE01-F002 | V: là ổ mạng ánh xạ tới share | ShellBags, Jump List, LNK | 2015-03-23 20:27:24–20:27:33 | High | NIST-confirmed; chưa kiểm GUI |
| CASE01-F003 | Tập kết dữ liệu mật tại `Desktop\S data` (sau đó bị xóa) | ShellBags | 2015-03-24 13:40:13–13:57:40 | Medium | NIST-confirmed; chưa kiểm GUI |
| CASE01-F004 | `winter_whether_advisory.zip` được copy vào USB RM#2 (E:) và mở | ShellBags, LNK | 2015-03-24 13:59:38–14:01:32 | High | **Verified (GUI)** + NIST-confirmed |
| CASE01-F005 | Ghi CD với thư mục đổi tên viết tắt (CDBurn) | ShellBags, LNK | 2015-03-24 19:54:35–20:44:18 | High | **Verified (GUI)** + NIST-confirmed |
| CASE01-F006 | Google Drive được dùng 23–25/03 | ShellBags, Prefetch | 2015-03-23 20:05:34 – 2015-03-25 15:21:31 | Medium | NIST-confirmed một phần (lần chạy cuối); điểm .pf tạo muộn chưa giải thích |
| CASE01-F007 | Cài và chạy Eraser, CCleaner; thùng rác trống | Prefetch, ShellBags, RBCmd | 2015-03-25 14:50:14–15:18:29 | High | NIST-confirmed; chưa kiểm GUI |
| CASE01-F008 | Soạn và xuất XPS thư xin nghỉ việc | LNK, Prefetch, Jump List | 2015-03-24 18:48:40; 2015-03-25 15:24–15:29 | High | NIST-confirmed; chưa kiểm GUI |

Chi tiết: `candidate_findings.md`, `manual_evidence.md`.

## 8. Hạn chế và đề xuất cho tuần 2

### Hạn chế đã gặp
1. **Mất timestamp khi copy:** `Copy-Item` đổi Created/Accessed của .lnk và .pf thành thời điểm copy (2026-10-28 03:16:40Z). Đã khắc phục bằng cách chạy LECmd/JLECmd/PECmd trực tiếp trên ổ F: (read-only). Output cũ trong `output/*/20261028_103708` cho LNK/Prefetch **không dùng cho timeline**.
2. **Log thu thập ghi sai múi giờ ở lượt 1** (giờ local nhưng hậu tố Z). Đã sửa script; lượt 2 (03:19Z) là lượt chính thức.
3. **Suy luận bị bác bỏ:** giả thuyết "Google Drive bị gỡ rồi cài lại" (dựa vào .pf tạo muộn + UNINST.EXE) sai – NIST cho biết lần gỡ là CCleaner và iCloud. Minh chứng cho việc phải tách observed và inferred.
4. **Chưa giải thích:** `.pf` của GOOGLEDRIVESYNC tạo lúc 15:21:40Z ngày 25/03 dù Google Drive đã dùng từ 23/03; `D:\de` First interacted sớm hơn mốc đổi tên của NIST ~46 phút.
5. **Ký tự ổ không định danh thiết bị:** E: là 2 USB khác nhau trong cùng một buổi sáng.
6. **Hành vi trên file system** (đổi tên, xóa, format) không có trong các artifact đã phân tích.

### Đề xuất tuần 2
1. Bổ sung **MFTECmd** cho `$MFT` và `$UsnJrnl:$J` để bắt đổi tên/xóa file (3 hành động ✗ ở mục 6).
2. Đọc **USBSTOR / MountedDevices / EMDMgmt** để phân biệt RM#1 và RM#2 bằng serial.
3. Map SID → user qua `ProfileList`.
4. Chuẩn hóa ShellBags vào pipeline của Nam (`shellbags_importer.py` dùng logic của `sbecmd_to_findings.py`).
5. Đề xuất correlation rule cho Thi:
   - Cùng **tên file** trong LNK và ShellBag (`...\file.zip`) trong cửa sổ ≤ 10 giây ⇒ "mở file từ thư mục X".
   - ShellBag **CDBurn** + LNK có DriveType Optical ⇒ "ghi/kiểm tra đĩa quang".
   - Prefetch công cụ wipe/cleaner + Recycle Bin trống ⇒ "nghi vấn anti-forensics".
   - Correlation window tối thiểu vài giây (hai hive lệch ~2 giây).
