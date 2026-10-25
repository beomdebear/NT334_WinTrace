# WinTrace – Windows Forensic Artifacts Reference Guide

## 1. Giới thiệu
Tài liệu này cung cấp cơ sở lý thuyết và hướng dẫn phân tích pháp chứng chuyên sâu cho 5 nhóm Windows Artifacts trọng tâm được khai thác trong dự án **WinTrace**:
1. **ShellBags** (Lịch sử duyệt thư mục & Explorer Interaction)
2. **Windows Prefetch** (Dấu vết thực thi chương trình)
3. **Shortcut LNK & Recent Files** (Tương tác tệp tin)
4. **Recycle Bin Metadata** (Hành vi xóa tệp tin)
5. **Windows Event Logs (EVTX)** (Nhật ký hệ thống & bảo mật)

---

## 2. ShellBags Investigation (Ngày 3)

### 2.1. Vị trí lưu trữ
- Windows 7/8/10/11:
  - `UsrClass.dat`: `C:\Users\<Username>\AppData\Local\Microsoft\Windows\UsrClass.dat`
  - Hive path: `HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` và `...\Bags`
- Thư mục mạng / File dialogs:
  - `NTUSER.DAT`: `C:\Users\<Username>\NTUSER.DAT`
  - Hive path: `HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\BagMRU` và `...\Bags`

### 2.2. Cơ chế hoạt động & Ý nghĩa pháp chứng
- **Mục đích của Windows:** Lưu lại cấu hình hiển thị (view settings, icon size, window position, sort order) của từng thư mục mà người dùng mở qua Windows Explorer.
- **Cấu trúc `BagMRU`:** Cấu trúc dạng cây phân cấp (tree-like structure) tương ứng với cấu trúc thư mục trên đĩa. Mỗi subkey đại diện cho một thư mục con, chứa giá trị `MRUListEx` (Most Recently Used).
- **Ý nghĩa pháp chứng:**
  - Chứng minh sự **tồn tại** của thư mục trên hệ thống (kể cả khi thư mục đã bị xóa hoặc nằm trên USB/ổ cứng ngoài đã tháo ra).
  - Chứng minh **người dùng cụ thể** (thông qua user hive) đã điều hướng qua thư mục đó.
  - Cung cấp timestamp: Thời điểm thư mục được tạo, sửa đổi và thời điểm tương tác gần nhất (`MRU time`).

### 2.3. Giới hạn pháp chứng
- ShellBags chứng minh người dùng duyệt tới **thư mục**, **không** chứng minh người dùng mở hoặc đọc nội dung từng file cụ thể bên trong thư mục.

---

## 3. Windows Prefetch (Ngày 4)

### 3.1. Vị trí & Cơ chế
- Đường dẫn: `C:\Windows\Prefetch\*.pf`
- Quy tắc đặt tên: `<Tên_Executable>-<Hash_8_ký_tự>.pf` (Ví dụ: `WINWORD.EXE-5C48A1B2.pf`).
- Hash được tính toán dựa trên đường dẫn tuyệt đối của file thực thi. Các tham số dòng lệnh khác nhau (đối với một số service/hosting processes như `svchost.exe`, `dllhost.exe`) sẽ sinh hash khác nhau.

### 3.2. Cấu trúc phiên bản Prefetch
- Windows 7: Version 23
- Windows 8/8.1: Version 26
- Windows 10 & 11: Version 30 (nén định dạng MAM - XPRESS Huffman algorithm)

### 3.3. Dữ liệu pháp chứng có giá trị cao
1. **Execution Count (Run count):** Tổng số lần file thực thi được chạy.
2. **Execution Timestamps:**
   - Windows 10/11 lưu trữ **tối đa 8 mốc thời gian thực thi gần nhất** (1 mốc trong header và 7 mốc phụ).
3. **Loaded Files / DLL Dependencies:** Danh sách mọi tệp tin, DLL, font, module mà tiến trình tải vào bộ nhớ trong 10 giây đầu tiên khởi chạy.
   - *Giá trị đặc biệt:* Nếu ứng dụng như `WINWORD.EXE`, `notepad.exe` mở một file tài liệu, đường dẫn của file tài liệu đó thường xuất hiện trong danh sách loaded files của Prefetch!

### 3.4. Giới hạn pháp chứng
- Mặc định trên Windows Server hoặc hệ thống chạy SSD cũ, Prefetch có thể bị tắt (`EnablePrefetcher = 0`).
- Prefetch ghi nhận ở cấp độ máy trạm (System-wide), không gắn trực tiếp với User SID trong file header (cần đối chiếu với Event Log 4688 hoặc UserAssist).

---

## 4. Shortcut Files (LNK) & Jump Lists (Ngày 4)

### 4.1. Vị trí lưu trữ
- `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`
- Jump Lists: `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*` và `CustomDestinations\*`

### 4.2. Dữ liệu trích xuất từ cấu trúc Shell Link (.lnk)
- **Target File Timestamps:** Ngày giờ tạo (Creation), sửa đổi (Modification), và truy cập (Access) của file đích tại thời điểm shortcut được tạo hoặc cập nhật.
- **Target File Size:** Kích thước byte của file đích.
- **Volume Information:** Loại ổ đĩa (Fixed, Removable, Network), Volume Serial Number, Drive Letter.
- **Tracker Data Block:**
  - NetBIOS Computer Name của máy tính tạo file.
  - MAC Address của card mạng máy tính tạo file (nếu UUID format version 1).

### 4.3. Ý nghĩa pháp chứng
- Cung cấp bằng chứng mạnh mẽ rằng người dùng đã tương tác trực tiếp với một tài liệu cụ thể.
- Cho phép xác định tài liệu gốc nằm trên USB nào nhờ Volume Serial Number.

---

## 5. Windows Recycle Bin ($I / $R Metadata)

### 5.1. Cấu trúc lưu trữ
- Đường dẫn: `C:\$Recycle.Bin\<User_SID>\`
- Khi người dùng xóa file bằng phím `Delete`:
  - File gốc được đổi tên thành: `$R<6_ký_tự_ngẫu_nhiên>.<ext>` (chứa dữ liệu file gốc).
  - Hệ thống tạo file index tương ứng: `$I<6_ký_tự_ngẫu_nhiên>.<ext>` (chứa metadata).

### 5.2. Cấu trúc file `$I` (Windows 10/11 - Version 2)
- Header: Version 2 (8 bytes, giá trị `0x02`)
- Original File Size (8 bytes, int64)
- Deletion Timestamp (8 bytes, Windows FILETIME format UTC)
- Original File Path (Unicode string, tối đa 520 ký tự)

### 5.3. Ý nghĩa pháp chứng
- Gắn kết chặt chẽ hành vi xóa với **User SID** (do thư mục nằm trong SID tương ứng).
- Phục hồi chính xác 100% đường dẫn gốc và thời điểm xóa, chứng minh ý chí tiêu hủy bằng chứng.

---

## 6. Windows Event Logs (EVTX)

| Event ID | Log Provider | Ý nghĩa pháp chứng |
|:---:|---|---|
| **4624** | Security | Đăng nhập thành công (Kiểm tra Logon Type: 2-Interactive, 3-Network, 10-RemoteDesktop, User SID, IP) |
| **4625** | Security | Đăng nhập thất bại (Dấu hiệu Brute-force hoặc dò mật khẩu) |
| **4688** | Security | Khởi tạo tiến trình (Process Creation - New Process Name, Parent Process, Process CommandLine) |
| **4663** | Security | Truy cập đối tượng file/registry (Read, Write, Delete access mask) |
| **1102** | Security | Nhật ký bảo mật bị xóa có chủ đích (Audit Log was cleared - Hành vi che giấu dấu vết) |
| **7045** | System | Dịch vụ mới được cài đặt (New service installed - Dấu hiệu mã độc hoặc persistence) |

---

## 7. Bảng tổng hợp đối soát chéo (Cross-Artifact Correlation Matrix)

| Hoạt động của đối tượng | Artifact 1 | Artifact 2 | Artifact 3 | Tiêu chí xác minh chéo (Cross-Validation) |
|---|---|---|---|---|
| **Duyệt & Tìm kiếm thư mục** | ShellBags (`UsrClass.dat`) | File System MFT ($STANDARD_INFO) | Explorer History | Trùng khớp đường dẫn thư mục, thời điểm `MRUList` xảy ra trước khi mở file |
| **Mở tài liệu nhạy cảm** | Shortcut LNK (`Recent`) | Prefetch (`WINWORD.EXE.pf`) | EVTX 4688 (`WINWORD.EXE`) | File LNK trỏ đến tài liệu; Prefetch ghi nhận mở app và nạp file; EVTX xác nhận Parent PID |
| **Xóa file phi tang** | Recycle Bin `$I` file | EVTX 4663 (DELETE mask) | USN Journal / MFT Record | Timestamp `$I` khớp thời gian xóa; User SID của thư mục `$Recycle.Bin` trùng với user đang logon |
