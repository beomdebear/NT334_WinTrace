# Artifact Validation – Tuần 2 – CASE01

**Người thực hiện:** Phúc – Windows Forensic Artifact Analyst
**Phạm vi:** Rà soát dữ liệu tuần 1, kiểm chứng ShellBags bằng công cụ độc lập, kiểm thử import vào pipeline của Nam, đối chiếu chéo ShellBags với LNK / Jump List / Prefetch / Registry.
**Quy ước:** giờ UTC (hậu tố Z); giờ máy nghi phạm = UTC − 4h (EDT). Ba mức kết luận: **Observed** · **Inferred** · **NIST-confirmed**.

---

## 1. Nguồn output nào được dùng, nguồn nào không

| Output | Đầu vào của tool | Timestamp file system | Dùng cho timeline? | Vị trí trong repo |
|---|---|---|---|---|
| SBECmd `Deduplicated.csv` | Hive **bản copy** (`evidence_work/hives`) | Không dùng (timestamp nằm trong hive) | **Có** | `tool_output/sbecmd/` |
| RBCmd | `$Recycle.Bin` bản copy | Không dùng (timestamp nằm trong `$I`) | Có (0 file) | – |
| LECmd, JLECmd, PECmd lượt `20261028_103708` | **Bản copy** bằng `Copy-Item` | **Sai**: Created/Accessed của `.lnk`, `.pf`, `*-ms` = 2026-10-28 03:16:40Z | **KHÔNG** | không đưa lên |
| LECmd, JLECmd, PECmd lượt `fromF` | **Ổ mount read-only F:** | Đúng | **Có** | `tool_output/lecmd/`, `jlecmd/`, `pecmd/` |
| `registry_usb_network.csv` | Hive bản copy, đọc bằng python-registry | Không dùng | Có | `tool_output/registry/` |

SHA-256 của mọi output trong repo: mục 8.

> Quy tắc cho pipeline: **không import** bất kỳ output LNK / Jump List / Prefetch nào có `SourceCreated` năm 2026. Test `test_timestamps_are_utc_and_inside_case_window` chặn trường hợp này cho ShellBags.

## 2. Kiểm tra nhất quán dữ liệu tuần 1

| Kiểm tra | Kết quả |
|---|---|
| `shellbags_findings.csv` (v2) vs `results/case01_shellbags_events.csv` (unified): cùng tập `event_id` | ✅ 383 = 383 |
| Cùng timestamp, `timestamp_type`, `evidence_reference`, `validation_status` cho từng event | ✅ (test `test_v2_and_unified_describe_same_events`) |
| Số event verified khớp `manual_evidence.md` | ✅ 30 |
| Mọi dòng SBECmd được tham chiếu | ✅ 109/109 (test `test_every_sbecmd_row_is_traceable`) |
| Timestamp đều UTC, không có mốc của máy phân tích | ✅ min 2014-12-16T16:10:26Z, max 2015-03-25T15:30:09Z |
| Tài liệu tuần 1: "hai hive lệch nhau ~2 giây" | ❌ **Sai**, đo thực tế 0–33 giây (mục 4.3). Đã sửa trong `artifact_reference_case01.md` |
| Tài liệu tuần 1: F004 "nhận dạng thiết bị (USBSTOR) chưa kiểm" | ✅ Đã giải quyết (mục 6, tình huống S2) |
| Tài liệu tuần 1: "quick-format RM#2 – ✗ không có artifact" | ◐ Nay có dấu vết Registry (EMDMgmt đổi VSN lúc 21:02:34Z) |

## 3. Kiểm chứng ShellBags bằng công cụ độc lập

Ba công cụ khác nhau đọc **cùng một key BagMRU**:

| Finding | Hive | Key (dưới `BagMRU`) | SBECmd | ShellBags Explorer (tuần 1) | python-registry (tuần 2) | Kết quả |
|---|---|---|---|---|---|---|
| F001 | UsrClass | `\8\0\0\2` (MRU0 = pricing decision) | 20:28:17 | 20:28:17.754 | 20:28:17.754148 | ✅ |
| F001 | UsrClass | `\8\0\0\2\0` (design) | 20:24:12 | 20:24:12.943 | 20:24:12.943099 | ✅ |
| F001 | UsrClass | `\8\0\0\2\1` (pricing decision) | 20:24:15 | 20:24:15.814 | 20:24:15.814305 | ✅ |
| F001 | NTUSER | `\0\0\0\2\0` (design) | 20:24:14 | 20:24:14.753 | 20:24:14.753103 | ✅ |
| F004 | UsrClass | `\1\0\1\4` (MRU0 = zip) | 14:01:29 | 14:01:29.766 | 14:01:29.766236 | ✅ |
| F005 | UsrClass | `\1\3` (D: CDBurn, MRU0 = de) | 20:44:13 | 20:44:13.155 | 20:44:13.155819 | ✅ |

- `MRUListEx` của `\8\0\0\2` = `[1, 2, 5, 4, 3, 0]`: value 1 (pricing decision) đứng đầu, khớp MRU0 trong SBECmd.
- Xác nhận ngữ nghĩa: **First Interacted của SBECmd = LastWrite của key con** (`\8\0\0\2\0` = 20:24:12.943 = First Interacted của `design`).
- SBECmd làm tròn xuống giây. Correlation không nên so sánh dưới mức giây.

## 4. Timestamp dễ bị diễn giải sai (định lượng trên 383 event)

| # | Vấn đề | Số event | Ví dụ | Xử lý trong dữ liệu |
|---|---|---|---|---|
| 4.1 | **Target metadata** (Created/Modified/Accessed của thư mục trong shell item) không phải hoạt động người dùng | 168 | `CASE01-SB0001` 2014-12-16 (Modified của file zip, trước kịch bản 3 tháng) | `semantic_class=target_metadata`, `is_user_activity=false` |
| 4.2 | **Key LastWrite của mục MRU > 0** không gắn được với thư mục đó (key cha bị ghi vì thư mục khác) | 63 / 104 | burst 20:28:17Z | `semantic_class=registry_write_unattributed` |
| 4.3 | **Cùng một lần duyệt ghi ở cả 2 hive**, lệch 0–33 giây. Không phải 2 bằng chứng độc lập | 28 event, 10 thư mục | `SB0115`/`SB0119`: share, UsrClass 20:23:28 – NTUSER 20:24:01 (33 s) | `cross_hive_twin_ids` |
| 4.4 | **Burst**: một lần ghi registry hiện thành nhiều event cùng giây | 12 mốc có ≥ 3 event (cùng hive) | 13 event lúc 2015-03-25T15:30:06Z | `registry_write_burst` |
| 4.5 | **FAT chỉ lưu ngày truy cập**: Accessed = 00:00 giờ máy = 04:00:00Z | 7 | Accessed của zip trên E: | `timestamp_precision=fat_date_only` |
| 4.6 | Shell item dùng FAT time: độ phân giải 2 giây | 168 | 0 event có giây lẻ (đã kiểm) | `timestamp_precision=fat_2s` |
| 4.7 | Ký tự ổ không định danh thiết bị: E: = 2 USB khác nhau trong cùng buổi sáng | – | `E:\RM#1\...` (RM#1) vs `E:\Secret Project Data` (RM#2) | `volume_map_case01.csv` |
| 4.8 | Cùng đối tượng, 2 đường dẫn: `V:\...` và `\\10.11.11.128\secured_drive\...` | – | `final_meeting.pptx` | `volume_map_case01.csv` (alias V:) |

Shell item timestamp được Windows ghi ở **UTC**. Xác nhận: Accessed (FAT, chỉ có ngày) hiện `04:00:00Z` = nửa đêm EDT, và Created của zip `13:59:38Z` khớp mốc NIST 09:59 EDT.

## 5. Kiểm thử import vào pipeline của Nam

Chạy trên `src/normalizer.py` và `src/storage.py` của nhánh `dev`, với dữ liệu CASE01 thật:

| Kiểm tra | Kết quả |
|---|---|
| `PlasoNormalizer.normalize_file_with_report(results/case01_shellbags_events.csv)` | ✅ 383 event, 0 lỗi |
| `TimelineStore.insert_events` | ✅ 383 dòng, `evidence_reference` / `timestamp_type` / `validation_status` đủ 383/383, 30 verified |
| Chạy lại lần 2 | ✅ 0 dòng mới (idempotent) |
| Import đồng thời `shellbags_findings.csv` **và** `case01_shellbags_events.csv` | ⚠️ **766 dòng cho 383 `event_id`**: fingerprint khác nhau nên không khử trùng được |
| Đường dẫn UNC sau normalize | ❌ `\\10.11.11.128\secured_drive\...` → `\10.11.11.128\secured_drive\...` (`src/schema.py::normalize_windows_path` gộp `\\` đầu) |

Test đã thêm: `tests/test_case01_shellbags_import.py`, 11 test, chạy trên file bàn giao thật. Kết quả cả bộ test: **30 passed, 1 xfailed**. Test xfail ghi lại lỗi UNC: khi đã sửa, test sẽ XPASS và cần gỡ marker.

**Đề xuất cho Nam / Quyên:**
1. **Chỉ import `results/case01_shellbags_events.csv`** (định dạng unified, có `parser`, `username`, `user_sid`, metadata có cấu trúc). `shellbags_findings.csv` là bản tham chiếu v2, không đưa vào DB cùng lúc.
2. Sửa `normalize_windows_path` để giữ tiền tố UNC, ví dụ:
   ```python
   unc = cleaned.startswith("\\\\")
   cleaned = re.sub(r'\\+', r'\\', cleaned)
   if unc:
       cleaned = "\\" + cleaned
   ```
3. Cân nhắc khóa duy nhất `(event_id, source_label)` để chặn việc nạp trùng một nguồn từ hai định dạng.

## 6. Đối chiếu chéo artifact – 5 tình huống CASE01

Tham chiếu dòng: `LECmd Lx` = `tool_output/lecmd/LECmd_Output_fromF.csv`, `JL Lx` = `tool_output/jlecmd/AutomaticDestinations_fromF.csv`, `PF Lx` = `tool_output/pecmd/PECmd_Output_fromF.csv`, `REG` = `tool_output/registry/registry_usb_network.csv`.

### S1 – Truy cập network share và mở file (F001, F002)

| Artifact | Bằng chứng | UTC |
|---|---|---|
| ShellBags | `SB0117` share (LastInteracted, UsrClass); `SB0123`–`SB0144` các thư mục con (First Interacted); `SB0158` pricing decision MRU0 | 20:23:28 → 20:28:17 |
| Registry | Map Network Drive MRU `a = \\10.11.11.128\secured_drive`; MountPoints2 `##10.11.11.128#secured_drive` | 20:26:04 |
| Jump List | Excel 12 mở `...\pricing decision\(secret_project)_pricing_decision.xlsx` (JL L23); `V:\Secret Project Data\final\[secret_project]_final_meeting.pptx` (JL L21) | 20:26:53, 20:27:33 |
| LNK | `(secret_project)_pricing_decision.xlsx` (LECmd L2), `[secret_project]_final_meeting.pptx` qua UNC (LECmd L15) | 20:26:53, 20:27:33 |
| Prefetch | **Không có** `EXCEL.EXE`/`POWERPNT.EXE` .pf | – |

- **Observed:** duyệt share; ánh xạ ổ mạng tới share; Excel mở file pricing_decision.xlsx trên share; file final_meeting.pptx được mở.
- **Inferred:** V: là ổ ánh xạ tới share. Cùng tên file `final_meeting.pptx` xuất hiện qua V: (Jump List) và qua UNC (LNK) cùng giây 20:27:33.
- **Giới hạn:** không có Prefetch của Excel/PowerPoint, nên không xác nhận thực thi bằng Prefetch. Nguyên nhân chưa rõ (Prefetch Win7 giới hạn 128 file, hiện có 95; có thể bị dọn). Không có bằng chứng sao chép trong các artifact này.
- **NIST-confirmed:** 16:23 EDT kết nối, 16:26 EDT map V:, 16:28 EDT copy 2 file.

### S2 – Hai USB khác nhau cùng mang ký tự E: (F004)

| Artifact | RM#1 | RM#2 |
|---|---|---|
| USBSTOR serial (SanDisk Cruzer Fit) | `4C530012450531101593`, first install 2015-03-23 18:31:11Z, key LW 2015-03-24 13:38:00Z | `4C530012550531106501`, first install 2015-03-24 13:58:33Z |
| EMDMgmt (nhãn, VSN) | "Authorized USB", `5C754D3E`, LW 2015-03-23 18:31:12Z | "IAMAN $", `9E6A5B82`, LW 13:58:34Z; sau đó `B4D85399`, LW 21:02:34Z |
| MountPoints2 | `{662626a6-…}` LW 2015-03-24 13:38:00Z | `{a2f2048e-…}` LW 21:02:33Z |
| LNK / Jump List | LECmd L14, L16; JL L12–L14, L20, L22: `E:\RM#1\...`, VSN `5C754D3E` (2015-03-23 18:37–18:38Z) | JL L9 `E:\Secret Project Data\design\winter_whether_advisory.zip`, VSN `9E6A5B82` (14:01:23Z) |
| ShellBags | `SB0172`–`SB0176` `E:\RM#1\...` (13:38:31–13:38:52Z ngày 24/03) | `SB0260`–`SB0270` `E:\Secret Project Data\...` (14:00:19–14:01:32Z); Target Created của zip `SB0254` 13:59:38Z |

- **Observed:** hai thiết bị USB khác serial; hai volume khác VSN; file zip được mở trên volume `9E6A5B82`.
- **Inferred:** volume `9E6A5B82` thuộc USB serial `…106501` (RM#2), và `5C754D3E` thuộc `…101593` (RM#1). Liên kết dựa trên trùng thời điểm (≤ 1 giây) giữa USBSTOR và EMDMgmt, **không** dựa trên ID tường minh, vì tên khóa EMDMgmt bị cắt cụt.
- **Inferred:** RM#2 được format lúc ~21:02Z (cùng nhãn, VSN mới).
- **NIST-confirmed:** RM#1 cắm 14:31 EDT ngày 23/03 và 09:38 EDT ngày 24/03; RM#2 cắm 09:58 EDT; quick-format RM#2 17:02 EDT.
- **Chưa giải thích:** `SB0342` `E:\Secret Project Data\progress` lúc 20:54:07Z, không có VSN nên không biết là thiết bị nào (theo thời gian, nhiều khả năng là RM#2 trước khi format).

### S3 – Chuẩn bị và ghi đĩa CD (F005)

| Artifact | Bằng chứng | UTC |
|---|---|---|
| ShellBags (CDBurn) | `SB0309` `D:\de` First Interacted; `SB0317` `D:\tr`; `SB0327`–`SB0329` `pd`, `prop`, `prog`; `SB0330` `D:\de` MRU0 | 19:54:35; 20:01:54; 20:44:10–11; 20:44:13 |
| ShellBags | `SB0312`–`SB0316` duyệt `D:\de\winter_whether_advisory.zip\ppt\slides`; `SB0337` `...\slideMasters` | 19:54:43–46; 20:44:18 |
| Jump List | JL L4–L7 `D:\de\winter_whether_advisory.zip...`, VSN `E297F1A5` | 20:44:13–18 |
| LNK | LECmd L13 `winter_whether_advisory.zip.lnk`: Created 14:01:23Z (lúc đó trên E:), Modified 20:44:18Z → `D:\de\...`, VSN `E297F1A5`, ổ quang | 20:44:18 |
| LNK | `CD Drive.lnk` VSN `A58AD72A` (L4); Koala/Penguins/Tulips VSN `AE88F176` (L3, L6, L7, L12) | 20:47:22–21:01:14 |
| Registry | MountedDevices `\DosDevices\D:` = VMware SATA CD | – |

- **Observed:** thư mục `de`, `tr`, `pd`, `prop`, `prog` trong khu chờ ghi đĩa của D:; file zip được mở từ `D:\de`; có **3 volume quang khác VSN** (`E297F1A5`, `A58AD72A`, `AE88F176`).
- **Inferred:** `de/pd/prog/prop/tr` là viết tắt của 5 thư mục dữ liệu mật.
- **Mâu thuẫn với NIST, chưa giải thích:** NIST ghi đổi tên thành `de/pd/...` lúc 16:40 EDT (20:40Z), nhưng `D:\de` đã có từ **19:54:35Z**, file zip đã được mở từ `D:\de` lúc **19:54:43Z**, và `D:\tr` có từ **20:01:54Z**. NIST mô tả 15:40–16:35 EDT là giai đoạn "tập ghi đĩa". Có thể lần tập đã dùng cùng tên viết tắt, nhưng **không chứng minh được** từ các artifact này. Thi và Quyên không nên dùng mốc 20:40Z làm ground truth cho tên `de` khi chấm.

### S4 – Công cụ xóa dấu vết (F007)

| Artifact | Bằng chứng | UTC (25/03) |
|---|---|---|
| Prefetch | `ERASER 6.2.0.2962.EXE` installer (PF L25) 14:50:14; `ERASER.EXE` 2 lần, cuối 15:13:30 (L26); `CCSETUP504.EXE` 14:57:56 (L8); `CCLEANER64.EXE` 2 lần, cuối 15:15:50 (L7); `UNINST.EXE` 15:18:29 (L81); `MSIEXEC.EXE` 15:18:54 / 15:19:11 (L42–L43) | |
| ShellBags | `SB0298` `Desktop\temp` (có từ 24/03 19:52:13Z); `SB0346` Recycle Bin 14:14:17; `SB0354`–`SB0356` Programs and Features 15:19:20 (burst 8) | |
| RBCmd | 0 file `$I` trong cả 3 SID | |

- **Observed:** Eraser và CCleaner được cài và chạy; Programs and Features được mở ngay sau `UNINST.EXE`; thùng rác trống.
- **Không chứng minh được:** Eraser đã xóa **file nào**. Prefetch của `ERASER.EXE` có thư mục `...\INFORMANT\DESKTOP` trong `Directories` nhưng không có `DESKTOP\TEMP` hay file nào trong đó: chỉ cho thấy Eraser có làm việc với thư mục Desktop, không xác định được đối tượng bị xóa. Thùng rác trống có thể do Empty Recycle Bin hoặc Shift+Delete. CCleaner chạy **không** có nghĩa là đã dọn dữ liệu (NIST: mở nhưng không làm gì).
- **NIST-confirmed:** 11:13 EDT Eraser xóa `Desktop\temp`; 11:14 EDT dọn thùng rác; 11:18 EDT gỡ CCleaner và iCloud.

### S5 – Thư xin nghỉ việc (F008): ví dụ chương trình–file có bằng chứng trực tiếp

| Artifact | Bằng chứng | UTC |
|---|---|---|
| Prefetch | `WINWORD.EXE` (PF L88): 3 lần, cuối 2015-03-25 15:24:48, .pf tạo 2015-03-24 18:32:25; **`FilesLoaded` chứa** `...\DESKTOP\RESIGNATION_LETTER_(IAMAN_INFORMANT).DOCX` | |
| Prefetch | `XPSRCHVW.EXE` (PF L96): 15:28:47; `FilesLoaded` chứa `...RESIGNATION_LETTER_(IAMAN_INFORMANT).XPS` | |
| LNK | `.docx` Created 2015-03-24 18:48:40, Modified 2015-03-25 15:29:08 (L9); `.xps` 15:28:33 (L10) | |
| Jump List | Word (Unknown AppId) `.docx` 15:29:08 (JL L19); XPS Viewer `.xps` 15:28:47 (JL L32) | |

- **Observed:** Word đã nạp file `.docx` (Prefetch `FilesLoaded`), file được mở lần đầu 24/03 18:48:40Z, lần cuối 25/03 15:29:08Z; XPS Viewer mở bản `.xps`.
- **Lưu ý:** `IEXPLORE.EXE` cũng có `RESIGNATION_LETTER...DOCX` trong `FilesLoaded`. Điều này **không** chứng minh Internet Explorer mở file. Có thể file được nạp qua hộp thoại chọn file hoặc khi tải lên. Đây là ví dụ false correlation cho R04.

## 7. Kết luận

| Tiêu chí tuần 2 (kế hoạch 1.4) | Trạng thái |
|---|---|
| Nam import được ShellBags | ✅ 383/383, 0 lỗi, idempotent (đã chạy thật, có test) |
| Timestamp quan trọng có giải thích forensic | ✅ `semantic_class`, `timestamp_precision` trên từng event; mục 4 |
| Evidence reference không mất khi chuyển đổi | ✅ 109/109 dòng SBECmd, 383/383 event |
| ≥ 3 tình huống CASE01 đối chiếu bằng artifact và/hoặc công cụ độc lập | ✅ 5 tình huống (mục 6) + 6 key BagMRU qua 3 công cụ (mục 3) |
| Suy luận chưa chứng minh được ghi rõ | ✅ mỗi tình huống có mục Inferred / Không chứng minh được / Chưa giải thích |

**Còn mở:** (1) lỗi UNC trong `normalize_windows_path` (Nam/Quyên); (2) mốc `D:\de` sớm hơn NIST; (3) không có Prefetch của Excel/PowerPoint; (4) chưa phân tích `$MFT`/`$UsnJrnl` cho hành vi đổi tên và xóa.

## 8. Integrity của output trong repo

| File | SHA-256 |
|---|---|
| `tool_output/sbecmd/Deduplicated.csv` | `1bad7daaf24e87efccd37d19902b142f08b6bbe06aedeee8979e20b6ffcd770b` |
| `tool_output/lecmd/LECmd_Output_fromF.csv` | `cf364cd3aa58ee559895faa2f4e5ad9a7367e785201a38d28f8a680d4085f162` |
| `tool_output/jlecmd/AutomaticDestinations_fromF.csv` | `2f5b90c0bbd68bd4c8de9e59bde1a8bdde10055a87cf27e26a22d3d7897fe282` |
| `tool_output/pecmd/PECmd_Output_fromF.csv` | `d1ee9a520059b374d253ec1d8af7c6dc1195924407f3b75367195ec4293f3ac3` |
| `tool_output/pecmd/PECmd_Output_Timeline_fromF.csv` | `b11dc0b6642d70b31d1c66d247361affbbbad0c4d7f77096162b2cd4597b8824` |
| `tool_output/registry/registry_usb_network.csv` | `522f2e053cd870231de7eb0199c36a891fca1c2397136976dcf8ca68f95cb4c2` |

Hive đầu vào: SHA-256 trong `case_notes/integrity.md`. Lệnh tái tạo: `scripts/registry_usb_check.py`, `scripts/to_team_schema.py` (xem README).
