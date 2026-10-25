# WinTrace – Unified Forensic Event Schema

## 1. Giới thiệu & Mục tiêu
Tài liệu này đặc tả **Event Schema** chuẩn hóa cho dự án **WinTrace**, được thống nhất cho toàn bộ hệ thống.

Do các công cụ trích xuất forensic (đặc biệt là Plaso / `log2timeline`) thu thập dữ liệu từ nhiều nguồn khác nhau với định dạng và cấu trúc trường đa dạng, việc chuẩn hóa dữ liệu đầu ra về một schema duy nhất là điều kiện tiên quyết để:
- Hợp nhất các bản ghi vào một **Super Timeline** thống nhất.
- Hỗ trợ công cụ phân tích truy vấn, lọc (targeted filtering) theo cú pháp nhất quán.
- Cung cấp đầu vào chuẩn cho **Correlation Engine** và **Cross-Validation Module**.
- Bảo toàn tính toàn vẹn và khả năng truy vết ngược lại bằng chứng gốc (chain of custody).

---

## 2. Đặc tả các trường trong Event Schema

Mỗi sự kiện (Event) trong WinTrace được định nghĩa bằng cấu trúc JSON / Dictionary gồm các trường bắt buộc và tùy chọn sau:

| Tên trường (Field) | Kiểu dữ liệu | Bắt buộc | Mô tả & Ý nghĩa pháp chứng | Ví dụ |
|---|:---:|:---:|---|---|
| `event_id` | `String` | Có | Định danh duy nhất của sự kiện trong timeline | `"EVT-20261025-001"` |
| `timestamp` | `String (ISO 8601)` | Có | Thời gian xảy ra sự kiện, chuẩn hóa theo múi giờ UTC (`YYYY-MM-DDTHH:MM:SS+00:00`) | `"2026-10-25T02:14:00+00:00"` |
| `timestamp_desc` | `String` | Có | Ngữ nghĩa của timestamp theo cơ chế hệ thống (MACB) | `"Last Time Executed"`, `"File Created"`, `"Date Deleted"`, `"Content Modification Time"` |
| `artifact_source` | `String` | Có | Tên nguồn artifact pháp chứng tạo ra sự kiện | `"Prefetch"`, `"LNK"`, `"ShellBags"`, `"RecycleBin"`, `"EVTX"` |
| `source_file` | `String` | Có | Đường dẫn hoặc tên file bằng chứng gốc được trích xuất | `r"C:\Windows\Prefetch\WINWORD.EXE-ABCD1234.pf"` |
| `target_path` | `String` | Có | Đường dẫn đối tượng (file, thư mục, executable) mà sự kiện tác động tới | `r"C:\Users\Alice\Documents\Project\confidential.docx"` |
| `user_sid` | `String` | Không | Security Identifier (SID) của người dùng liên quan (nếu artifact hỗ trợ) | `"S-1-5-21-1234567890-1001"` |
| `username` | `String` | Không | Tên tài khoản người dùng tương ứng | `"Alice"` |
| `message` | `String` | Có | Mô tả ngắn gọn, dễ đọc về hành vi/nội dung sự kiện | `"Executed WINWORD.EXE [Run count: 12]"` |
| `data_type` | `String` | Có | Định danh loại parser của Plaso hoặc WinTrace | `"windows:prefetch:execution"`, `"windows:lnk:link"` |
| `parser` | `String` | Có | Tên parser module chịu trách nhiệm trích xuất | `"prefetch"`, `"lnk"`, `"winreg/shellbags"` |
| `confidence_level` | `String` | Có | Mức độ tin cậy của bằng chứng: `HIGH`, `MEDIUM`, `LOW` | `"HIGH"` |
| `extra_attributes` | `Object` | Không | Các trường metadata chi tiết bổ trợ tùy theo từng loại artifact | `{"run_count": 12, "original_file_size": 24576}` |

---

## 3. Quy chuẩn ngữ nghĩa Timestamp (`timestamp_desc`)

Để tránh việc ngộ nhận thời gian trích xuất là thời điểm người dùng thực hiện hành vi, WinTrace phân loại rõ các ngữ nghĩa thời gian:

1. **Thực thi (Execution):**
   - `Last Time Executed`: Thời điểm gần nhất tiến trình được khởi chạy (Prefetch, Amcache, UserAssist).
   - `Previous Run Times`: Các mốc thời gian thực thi trước đó lưu trong Prefetch v30 (Windows 8/10/11 lưu tối đa 8 lần chạy).
2. **Hệ thống tệp (File System & Shortcuts):**
   - `File Created Time ($STANDARD_INFORMATION / $FILE_NAME)`
   - `Content Modification Time ($STANDARD_INFORMATION)`
   - `Last Access Time` (Lưu ý: `NtfsDisableLastAccessUpdate` có thể vô hiệu hóa cập nhật này).
   - `LNK Target File Creation / Modification`: Timestamps của file đích được ghi lại vào shortcut lúc tạo/cập nhật.
3. **Thao tác người dùng (User Navigation & Deletion):**
   - `BagMRU First/Last Interacted Time`: Thời điểm người dùng mở thư mục qua Explorer (ShellBags).
   - `Deletion Timestamp`: Thời điểm file bị đưa vào thùng rác được ghi trong `$I` header (Recycle Bin).
4. **Nhật ký hệ thống (Audit Logs):**
   - `Event Generated Time`: Thời điểm Windows Audit Log phát sinh bản ghi (Event ID 4624, 4688, 7045).

---

## 4. Ánh xạ từ Plaso (`log2timeline` / `psort`) sang WinTrace Schema

Khi xuất dữ liệu bằng lệnh:
```bash
psort.py -o json_line -w timeline.jsonl storage.plaso
```
Các trường được ánh xạ tương ứng vào WinTrace Schema:

| Plaso Field | WinTrace Standardized Field | Xử lý chuyển đổi |
|---|---|---|
| `timestamp` (microsecond epoch) | `timestamp` | Chuyển đổi thành ISO 8601 UTC string (`%Y-%m-%dT%H:%M:%S+00:00`) |
| `timestamp_desc` | `timestamp_desc` | Giữ nguyên hoặc chuẩn hóa chuỗi mô tả |
| `parser` | `parser` | Chuẩn hóa tên parser chính |
| `data_type` | `data_type` | Xác định `artifact_source` dựa trên namespace |
| `display_name` | `source_file` | Lưu đường dẫn file nguồn artifact |
| `path_hints` / `path` | `target_path` | Chuẩn hóa định dạng đường dẫn Windows (`\`) |
| `message` | `message` | Làm sạch chuỗi hiển thị tóm tắt |
| Dynamic attributes | `extra_attributes` | Đóng gói các thuộc tính riêng (VD: `run_count`, `file_size`) |

---

## 5. Ví dụ bản ghi sự kiện chuẩn hóa (Sample Event Record)

```json
{
  "event_id": "EVT-20261025-003",
  "timestamp": "2026-10-25T02:14:00+00:00",
  "timestamp_desc": "Last Time Executed",
  "artifact_source": "Prefetch",
  "source_file": "C:\\Windows\\Prefetch\\WINWORD.EXE-5C48A1B2.pf",
  "target_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "user_sid": "S-1-5-21-3928172839-1002",
  "username": "Alice",
  "message": "Executed WINWORD.EXE [Run Count: 14, Hash: 5C48A1B2]",
  "data_type": "windows:prefetch:execution",
  "parser": "prefetch",
  "confidence_level": "HIGH",
  "extra_attributes": {
    "run_count": 14,
    "prefetch_hash": "5C48A1B2",
    "volume_serial": "A8C2-4F10",
    "referenced_files": [
      "C:\\Users\\Alice\\Documents\\Project\\confidential_report.docx",
      "C:\\Windows\\System32\\kernel32.dll"
    ]
  }
}
```
