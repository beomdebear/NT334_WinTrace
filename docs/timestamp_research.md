# Windows Forensic Timestamp Semantics & Analysis

## 1. Tổng quan về các hệ thống biểu diễn thời gian trên Windows

Trong quá trình điều tra số trên Windows, một trong những thách thức lớn nhất của việc xây dựng Super Timeline là sự khác biệt giữa các chuẩn biểu diễn thời gian:

1. **Windows FILETIME (64-bit integer):**
   - Đơn vị: Khoảng thời gian tính bằng bội số 100 nano-giây (100-ns intervals).
   - Epoch: Bắt đầu từ ngày 01/01/1601 lúc 00:00:00 UTC.
   - Được sử dụng trong: NTFS ($STANDARD_INFORMATION, $FILE_NAME), Registry, Prefetch, LNK, Recycle Bin ($I).
2. **Unix Epoch (32-bit hoặc 64-bit POSIX time):**
   - Đơn vị: Số giây trôi qua kể từ 01/01/1970 00:00:00 UTC.
   - Sử dụng trong nhiều log parser và công cụ mã nguồn mở.
3. **Plaso Internal Time (Microsecond epoch):**
   - Đơn vị: Microseconds (10^-6 giây) kể từ 01/01/1970 00:00:00 UTC.
   - Plaso lưu trữ thời gian dưới dạng integer microseconds để dễ dàng sắp xếp phân loại.
4. **WinTrace Standard Time:**
   - Chuẩn hóa thành chuỗi **ISO 8601 UTC** (`YYYY-MM-DDTHH:MM:SS+00:00` hoặc kèm microseconds khi cần độ chính xác cao).

---

## 2. Mô hình MACB và Ngữ nghĩa chi tiết

Mỗi artifact hệ thống ghi nhận các thuộc tính thời gian với ý nghĩa khác nhau:

| Ký hiệu | Ý nghĩa viết tắt | Ý nghĩa trên NTFS | Ý nghĩa trên LNK / ShellBags |
|:---:|---|---|---|
| **M** | Modified | Nội dung tệp tin bị thay đổi lần cuối | File target modification time |
| **A** | Accessed | Tệp tin hoặc thư mục được truy cập lần cuối | LNK access time / ShellBag MRU time |
| **C** | Changed / Created / MFT Altered | $STANDARD_INFO: MFT record modified; FAT: Created | Shortcut creation time / Folder created |
| **B** | Birth / Created | Thời điểm tệp tin được khởi tạo trên volume hiện tại | File target creation time |

---

## 3. Cạm bẫy Timestamps và Kỹ thuật phát hiện (Gotchas & Anti-forensics)

### 3.1. Timestomping
- **Kỹ thuật:** Kẻ tấn công hoặc mã độc sử dụng các API như `SetFileTime()` để thay đổi 4 mốc thời gian trong thuộc tính `$STANDARD_INFORMATION` (SI) nhằm ngụy trang file độc hại thành file hệ thống cũ.
- **Dấu hiệu phát hiện trên Super Timeline:**
  - So sánh `$STANDARD_INFORMATION` (SI) với `$FILE_NAME` (FN): Thuộc tính `$FILE_NAME` chỉ được Windows Kernel cập nhật khi tạo/đổi tên file, người dùng thông thường không thể can thiệp bằng API tiêu chuẩn. Nếu SI < FN, đây là dấu hiệu chắc chắn của Timestomping.
  - Độ phân giải miligiây: Windows FILETIME có độ phân giải nano-giây. Các công cụ timestomping thủ công thường chỉ truyền giây/phút, dẫn đến phần fractional seconds bằng 0 (`.0000000`).

### 3.2. Cấu hình vô hiệu hóa Last Access Time
- Từ Windows Vista/7/10/11, khóa Registry:
  `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate` thường được đặt thành `1` hoặc `2` (disabled) để tăng tốc độ truy xuất I/O ổ đĩa.
- **Hệ quả:** Last Access Time của file NTFS có thể không cập nhật khi người dùng chỉ đọc file.
- **Giải pháp Cross-Validation:** Thay vì tin cậy Access time của NTFS, điều tra viên cần kiểm tra đồng thời **Prefetch** (thời điểm app chạy) và **LNK/Recent** (thời điểm shortcut được sinh ra).

### 3.3. Hiệu ứng Fast Startup & Hibernation
- Windows 10/11 kích hoạt chế độ Fast Startup (Hybrid Sleep/Hibernate) theo mặc định.
- Khi khởi động từ Fast Startup, Windows không tạo Event ID 6005/6006 mà tạo Kernel-Boot Event ID 27/25 hoặc resume events. Điều tra viên cần chú ý để không bỏ sót phiên làm việc liên tục.

---

## 4. Ứng dụng trong Correlation Rules (R01 - Temporal Proximity)

- Khoảng thời gian nghi vấn (correlation window $\Delta t$):
  - Khuyến nghị cửa sổ mặc định: $\Delta t = 5$ phút đối với chuỗi hành vi tương tác liên tục của người dùng (User-Interactive loop: duyệt folder -> mở file -> đóng file -> xóa).
  - Đối với các hành vi tự động bằng script hoặc malware, cửa sổ có thể thu hẹp về $\Delta t \le 10$ giây.
