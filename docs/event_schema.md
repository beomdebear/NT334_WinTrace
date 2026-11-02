# WinTrace – Unified Forensic Event Schema (v2)

## 1. Giới thiệu & Mục tiêu
Tài liệu này đặc tả **Event Schema** chuẩn hóa cho dự án **WinTrace** (phiên bản v2 – Tuần 2), được thống nhất cho toàn bộ hệ thống giữa các thành viên (Phúc, Thi, Nam, Quyên).

Do các công cụ trích xuất forensic (Plaso / `log2timeline`, `psort`, SBECmd, LECmd, PECmd, JLECmd) thu thập dữ liệu từ nhiều nguồn khác nhau với định dạng và cấu trúc trường đa dạng, việc chuẩn hóa dữ liệu đầu ra về một schema duy nhất là điều kiện tiên quyết để:
- Hợp nhất các bản ghi vào một **Super Timeline** thống nhất.
- Hỗ trợ công cụ phân tích truy vấn, lọc (targeted filtering) theo cú pháp nhất quán.
- Cung cấp đầu vào chuẩn cho **Correlation Engine** (R01–R05) và **Cross-Validation Module** (H1–H4).
- Bảo toàn tính toàn vẹn và khả năng truy vết ngược lại bằng chứng gốc (chain of custody) qua trường `evidence_reference`.
- Phân biệt rõ ràng giữa bằng chứng thực tế từ disk image (CASE01) và dữ liệu mô phỏng thử nghiệm qua `validation_status` và `case_id`.

---

## 2. Đặc tả các trường trong Event Schema (ForensicEvent v2)

Mỗi sự kiện (Event) trong WinTrace được định nghĩa bằng cấu trúc JSON / Dictionary / Dataclass gồm các trường sau:

| Tên trường (Field) | Kiểu dữ liệu | Bắt buộc | Mới ở v2 | Mô tả & Ý nghĩa pháp chứng | Ví dụ |
|---|:---:|:---:|:---:|---|---|
| `event_id` | `String` | Có | | Định danh duy nhất của sự kiện trong timeline | `"CASE01-SB0001"`, `"EVT-0001"` |
| `timestamp` | `String (ISO 8601)` | Có | | Thời gian xảy ra sự kiện, chuẩn hóa theo múi giờ UTC (`YYYY-MM-DDTHH:MM:SS+00:00`) | `"2014-12-16T16:10:26+00:00"` |
| `timestamp_desc` | `String` | Có | | Ngữ nghĩa của timestamp dạng mô tả đọc được | `"Last Time Executed"`, `"ShellItem Target Modified"` |
| `timestamp_type` | `String` | Không | **MỚI** | Mã định danh kỹ thuật chuẩn hóa của loại timestamp, dùng cho Correlation Engine xác định độ chính xác (FAT ±2s vs NTFS/Prefetch ms) | `"ShellItem_FolderModified"`, `"Prefetch_LastRun"` |
| `artifact_source` | `String` | Có | Mở rộng | Tên nguồn artifact pháp chứng tạo ra sự kiện (thuộc `VALID_ARTIFACTS`) | `"ShellBags"`, `"Prefetch"`, `"LNK"`, `"JumpLists"`, `"RecycleBin"`, `"EVTX"`, `"NTFS_MFT"`, `"Registry"` |
| `source_file` | `String` | Có | | File bằng chứng gốc được trích xuất (tên hive hoặc file) | `"UsrClass.dat"`, `"WINWORD.EXE-5C48A1B2.pf"` |
| `target_path` | `String` | Có | | Đường dẫn đối tượng (file, thư mục, executable) mà sự kiện tác động tới | `"Desktop\\This PC\\E:\\Secret Project Data"`, `"C:\\Program Files\\WINWORD.EXE"` |
| `evidence_reference` | `String` | Không | **MỚI** | Chuỗi tham chiếu truy vết ngược lại bằng chứng gốc (file dòng, offset, hive, slot, tool trích xuất) | `"Deduplicated.csv:L59 \| hive=UsrClass.dat \| BagPath=BagMRU\\1\\0 \| verified: ShellBags Explorer"` |
| `message` | `String` | Có | | Mô tả ngắn gọn, dễ đọc về hành vi/nội dung sự kiện | `"User navigated to folder Project via Windows Explorer"` |
| `data_type` | `String` | Có | | Định danh loại parser của Plaso hoặc WinTrace | `"windows:registry:bagmru"`, `"windows:prefetch:execution"` |
| `parser` | `String` | Có | | Tên parser module chịu trách nhiệm trích xuất | `"sbecmd"`, `"prefetch"`, `"lnk"`, `"winevt"` |
| `user_sid` | `String` | Không | | Security Identifier (SID) của người dùng liên quan | `"S-1-5-21-3928172839-1002"` |
| `username` | `String` | Không | | Tên tài khoản người dùng tương ứng | `"informant"`, `"Alice"` |
| `confidence_level` | `String` | Có | | Mức độ tin cậy của bằng chứng: `HIGH`, `MEDIUM`, `LOW` | `"HIGH"` |
| `validation_status` | `String` | Không | **MỚI** | Trạng thái kiểm chứng: `verified`, `unverified`, `synthetic`, `disputed` | `"verified"` |
| `case_id` | `String` | Không | **MỚI** | Mã vụ án / bộ dữ liệu nhằm tách biệt bằng chứng thật và dữ liệu thử | `"CASE01"`, `"SCENARIO_TEST"` |
| `extra_attributes` | `Object` | Không | | Các trường metadata chi tiết bổ trợ tùy theo từng loại artifact | `{"mru_order": 1, "node_slot": 14}` |

---

## 3. Danh mục chuẩn hóa (Controlled Vocabularies)

### 3.1. Nguồn Artifact (`VALID_ARTIFACTS`)
```python
VALID_ARTIFACTS = {
    "ShellBags",     # Duyệt thư mục qua Explorer (UsrClass.dat, NTUSER.DAT)
    "Prefetch",      # Dấu vết thực thi chương trình (.pf)
    "LNK",           # Shortcut Recent (.lnk)
    "JumpLists",     # Mới v2: Danh mục gần đây theo ứng dụng (AppID)
    "RecycleBin",    # Thùng rác ($I / $R)
    "EVTX",          # Windows Event Logs (Security, System, Application)
    "NTFS_MFT",      # Master File Table ($MFT, $LogFile)
    "Amcache",       # Amcache.hve (thực thi và cài đặt)
    "UserAssist",    # Registry UserAssist GUI execution
    "USNJournal",    # Mới v2: Change journal ($UsnJrnl)
    "Registry"       # Mới v2: Các khóa Registry khác (USBSTOR, MountPoints2, TimeZone)
}
```

### 3.2. Trạng thái kiểm chứng (`VALID_VALIDATION_STATUSES`)
- `verified`: Đã được kiểm chứng đối chiếu qua công cụ forensic độc lập (ví dụ: ShellBags Explorer, FTK Imager) hoặc khớp với Ground Truth của NIST.
- `unverified`: Dữ liệu trích xuất tự động từ công cụ, chưa được kiểm tra chéo thủ công.
- `synthetic`: Dữ liệu kịch bản mô phỏng sinh ra cho unit test / prototype (như scenario Alice 2026), **tuyệt đối không xem là evidence thật**.
- `disputed`: Có dấu hiệu mâu thuẫn thời gian, nghi ngờ ngụy tạo hoặc xung đột giữa các nguồn artifact.

### 3.3. Mã ngữ nghĩa kỹ thuật Timestamp (`VALID_TIMESTAMP_TYPES`)

| Mã `timestamp_type` | Nguồn Artifact | Ngữ nghĩa kỹ thuật & Giới hạn |
|---|---|---|
| `ShellBag_LastInteracted` | ShellBags | LastWrite của key cha khi entry ở vị trí MRU 0 (lần tương tác gần nhất) |
| `ShellBag_FirstInteracted` | ShellBags | LastWrite của key con khi tạo lần đầu (lần tương tác đầu tiên) |
| `ShellBag_KeyLastWrite` | ShellBags | LastWrite của key BagMRU nói chung (chỉ gắn chắc với MRU 0) |
| `ShellItem_FolderCreated` | ShellBags | Created time lưu trong shell item extension block (FAT time, độ phân giải 2 giây) |
| `ShellItem_FolderModified` | ShellBags | Modified time lưu trong shell item extension block (FAT time, 2 giây) |
| `ShellItem_FolderAccessed` | ShellBags | Accessed time lưu trong shell item extension block (FAT time, 2 giây) |
| `Prefetch_LastRun` | Prefetch | Lần thực thi gần nhất của tiến trình (tính bằng milli-giây) |
| `Prefetch_PreviousRun` | Prefetch | Các mốc thực thi trước đó (tối đa 7 mốc phụ trên Win8+) |
| `Prefetch_FileCreated` | Prefetch | Thời điểm file `.pf` được tạo (xấp xỉ lần chạy đầu + 10s) |
| `LNK_TargetCreated` | LNK | Creation time của file đích tại thời điểm tạo/cập nhật shortcut |
| `LNK_TargetModified` | LNK | Modification time của file đích ghi nhận trong shortcut |
| `LNK_TargetAccessed` | LNK | Last Access time của file đích ghi nhận trong shortcut |
| `JumpList_TargetModified` | JumpLists | Thời điểm cập nhật mục đích trong AutomaticDestinations |
| `RecycleBin_DeletionTime` | Recycle Bin | Thời điểm xóa file ghi trong header `$I` (FILETIME UTC) |
| `EVTX_EventGenerated` | EVTX | Thời điểm hệ điều hành sinh bản ghi sự kiện |
| `NTFS_SI_Created` | MFT | File Created time trong attribute `$STANDARD_INFORMATION` |
| `NTFS_SI_Modified` | MFT | File Modified time trong attribute `$STANDARD_INFORMATION` |

---

## 4. Xử lý đường dẫn ShellBags (`extract_drive_path_from_bagmru`)

ShellBags biểu diễn đường dẫn dạng cấu trúc cây từ `Desktop`:
- `Desktop\This PC\E:\Secret Project Data\design`
- `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Past Projects`

Để liên kết tương quan (Correlation R02) với các artifact khác (như LNK trỏ tới `E:\Secret Project Data\...` hoặc Jump Lists trỏ tới `\\10.11.11.128\secured_drive\...`), WinTrace tích hợp hàm chuẩn hóa:
```python
extract_drive_path_from_bagmru(bagmru_path) -> (drive_or_root, relative_path)
```
- `Desktop\This PC\E:\RM#1\Secret Project Data` $\rightarrow$ `('E:', 'RM#1\\Secret Project Data')`
- `Desktop\Computers and Devices\10.11.11.128\...` $\rightarrow$ `('\\\\10.11.11.128', 'secured_drive\\Past Projects')`

---

## 5. Đặc tả Correlation Finding Schema (CorrelationFinding v2)

Kết quả tương quan từ **Correlation Engine** được chuẩn hóa theo cấu trúc sau:

| Trường | Kiểu dữ liệu | Mới ở v2 | Mô tả |
|---|:---:|:---:|---|
| `finding_id` | `String` | | Mã phát hiện: `"FIND-001"` |
| `event_a_id` | `String` | | ID sự kiện thứ nhất (tương thích ngược) |
| `event_b_id` | `String` | | ID sự kiện thứ hai (tương thích ngược) |
| `event_ids` | `List[String]` | **MỚI** | Danh sách đầy đủ các Event ID tham gia chuỗi tương quan |
| `event_a_desc` | `String` | | Tóm tắt sự kiện A |
| `event_b_desc` | `String` | | Tóm tắt sự kiện B |
| `time_delta_seconds` | `Float` | | Khoảng cách thời gian (giây) |
| `time_delta_minutes` | `Float` | | Khoảng cách thời gian (phút) |
| `matched_rules` | `List[String]` | | Các rule đã khớp (`["R01", "R02", "R03"]`) |
| `confidence_score` | `Integer` | | Điểm tin cậy (0 – 100) |
| `confidence_level` | `String` | | Xếp loại: `HIGH`, `MEDIUM`, `LOW` |
| `explanation` | `String` | | Giải thích chi tiết căn cứ liên kết |
| `investigation_note` | `String` | **MỚI** | Ghi chú điều tra, cảnh báo độ chính xác FAT timestamp hoặc trạng thái unverified |
| `evidence_references` | `List[String]` | **MỚI** | Danh sách bằng chứng gốc phục vụ thẩm tra |
| `validation_status` | `String` | **MỚI** | Trạng thái xác nhận của finding |

---

## 6. Ví dụ bản ghi sự kiện chuẩn hóa (Sample Event Records v2)

### 6.1. Sự kiện ShellBags thực tế (CASE01)
```json
{
  "event_id": "CASE01-SB0001",
  "timestamp": "2014-12-16T16:10:26+00:00",
  "timestamp_desc": "ShellItem Target Modified",
  "timestamp_type": "ShellItem_FolderModified",
  "artifact_source": "ShellBags",
  "source_file": "UsrClass.dat",
  "target_path": "Desktop\\This PC\\E:\\Secret Project Data\\design\\winter_whether_advisory.zip",
  "message": "Modified của thư mục lưu trong shell item (FAT time, 2s): Desktop\\This PC\\E:\\Secret Project Data\\design\\winter_whether_advisory.zip",
  "data_type": "windows:registry:bagmru",
  "parser": "sbecmd",
  "user_sid": null,
  "username": "informant",
  "confidence_level": "LOW",
  "validation_status": "verified",
  "case_id": "CASE01",
  "evidence_reference": "Deduplicated.csv:L59 | hive=UsrClass.dat | BagPath=BagMRU\\1\\0\\1\\4 | Slot=0 | MRU=0 | ShellType=File | verified: ShellBags Explorer v2026.10.1 (CASE01-F004)",
  "extra_attributes": {
    "slot": "0",
    "mru": "0",
    "shell_type": "File"
  }
}
```

### 6.2. Sự kiện Prefetch (CASE01 / Plaso)
```json
{
  "event_id": "CASE01-PF0014",
  "timestamp": "2015-03-25T15:24:48+00:00",
  "timestamp_desc": "Last Time Executed",
  "timestamp_type": "Prefetch_LastRun",
  "artifact_source": "Prefetch",
  "source_file": "WINWORD.EXE-5C48A1B2.pf",
  "target_path": "C:\\Program Files\\Microsoft Office\\Office14\\WINWORD.EXE",
  "message": "Executed WINWORD.EXE [Run count: 18]",
  "data_type": "windows:prefetch:execution",
  "parser": "prefetch",
  "user_sid": null,
  "username": "informant",
  "confidence_level": "HIGH",
  "validation_status": "unverified",
  "case_id": "CASE01",
  "evidence_reference": "PECmd_output.csv:L42 | file=WINWORD.EXE-5C48A1B2.pf",
  "extra_attributes": {
    "run_count": 18,
    "volume_serial": "CA0C7A48"
  }
}
```
