# Artifact Reference – WinTrace / CASE01

Người soạn: Phúc (Windows Forensic Artifact Analyst) · Cập nhật: 2026-10-28
Evidence: NIST CFReDS Data Leakage Case – PC image (Windows 7), user `informant`
Quy ước giờ: mọi timestamp ở **UTC**. Giờ máy nghi phạm = UTC − 4h (EDT, xem `case_notes/timezone.md`).

> Mục đích: với mỗi artifact, ghi rõ (1) nằm ở đâu, (2) tool nào đọc, (3) từng timestamp nghĩa là gì,
> (4) **chứng minh được gì / KHÔNG chứng minh được gì**. Bảng (4) là đầu vào để Thi viết correlation rule
> và để phân biệt observed với inferred.

---

## 1. ShellBags (artifact trọng tâm)

| Mục | Nội dung |
|---|---|
| Vị trí (Win7+) | `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` và `\Bags` – nguồn chính |
| Vị trí phụ | `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` và `\Bags` – chủ yếu thư mục mạng/Desktop |
| File hive | `%UserProfile%\AppData\Local\Microsoft\Windows\UsrClass.dat`, `%UserProfile%\NTUSER.DAT` (+ `.LOG1`, `.LOG2`) |
| Tool trích xuất | SBECmd 2026.10.2 (`--dedupe`) |
| Tool kiểm chứng | ShellBags Explorer 2026.10.1 (time zone UTC), Registry Explorer 2026.10.1 |

**Cấu trúc**
- `BagMRU` là cây phản chiếu cây thư mục. Mỗi value đánh số (`0`, `1`, …) là một **shell item** (binary) đại diện cho một thư mục con; key con cùng số chứa cấp tiếp theo.
- `MRUListEx` lưu thứ tự truy cập gần nhất của các value trong key → cột **MRU position** (0 = gần nhất).
- `NodeSlot` trỏ sang `Bags\<slot>` – nơi lưu trạng thái hiển thị (kiểu view, kích thước cửa sổ).
- Ví dụ kiểm chứng: `secured_drive\Secret Project Data\design` = UsrClass `BagMRU\8\0\0\2` value 0, NodeSlot 30.

**Ngữ nghĩa timestamp**

| Timestamp | Lưu ở đâu | Ý nghĩa | Độ tin cậy |
|---|---|---|---|
| Key LastWrite | LastWrite của key BagMRU | Lần cuối key được ghi – **chỉ gắn chắc với mục MRU 0** | Cao cho MRU 0, thấp cho mục khác |
| Last interacted | SBECmd suy ra = LastWrite của key cha khi mục là MRU 0 | Lần gần nhất thư mục được tương tác | Trung bình–cao |
| First interacted | SBECmd suy ra = LastWrite của key con (khi được tạo lần đầu) | Lần đầu thư mục được tương tác | Trung bình |
| Created/Modified/Accessed (target) | Trong shell item (extension block 0xBEEF0004) | MAC của **thư mục/file đích** tại thời điểm ShellBag được ghi; dạng FAT, độ phân giải 2 giây | Không phải thời điểm truy cập |

**Chứng minh được:** thư mục (hoặc file zip, thư mục trên ổ ngoài/mạng/khu chờ ghi CD) đã được **hiển thị/tương tác qua Explorer** bởi user sở hữu hive; thư mục vẫn còn dấu vết dù đã bị xóa.

**KHÔNG chứng minh được:** file cụ thể nào được mở, sao chép hay xóa; thiết bị nào (chỉ có ký tự ổ); thời điểm của mọi lần truy cập (chỉ lần đầu/lần cuối); thư mục còn tồn tại.

**Quan sát thực tế trên CASE01**
- 109 ShellBag duy nhất (NTUSER.DAT + UsrClass.dat), xuất ra 383 event theo schema nhóm.
- Hai hive ghi cùng một thư mục lệch nhau ~2 giây (`design`: UsrClass 20:24:12, NTUSER 20:24:14) ⇒ correlation window nên ≥ vài giây.
- Thư mục `Desktop\S data` bị xóa bằng Shift+Delete lúc 14:07Z ngày 24/03 (theo NIST) nhưng ShellBags vẫn giữ toàn bộ cây thư mục con.
- Shell type `CDBurn` xác định thư mục nằm trong **khu chờ ghi đĩa** của ổ quang.
- Target Accessed `04:00:00` (= 00:00 EDT) là dấu hiệu hệ thống file **FAT** (chỉ lưu ngày truy cập).

---

## 2. LNK (Shortcut / Recent)

| Mục | Nội dung |
|---|---|
| Vị trí | `%UserProfile%\AppData\Roaming\Microsoft\Windows\Recent\*.lnk` |
| Tool | LECmd 2026.10.3 – **chạy trực tiếp trên ổ mount read-only F:** |
| Timestamp của chính file .lnk | Created ≈ **lần đầu** mở đích qua Shell; Modified ≈ **lần gần nhất** mở |
| Timestamp lưu trong .lnk | Created/Modified/Accessed của **file đích** tại lần mở |
| Thông tin khác | Đường dẫn đích (local/network), loại ổ (Fixed/Removable/Optical/Network), **volume serial**, volume label, kích thước file đích, MAC/MachineID |

**Chứng minh được:** file/thư mục đích đã được mở qua Shell; đích nằm trên loại ổ nào và volume serial nào.

**KHÔNG chứng minh được:** file đích còn tồn tại; nội dung file; mở bằng chương trình nào (xem Jump List); mọi lần mở giữa lần đầu và lần cuối.

**Lưu ý quan trọng:**
- Windows đặt tên LNK theo **tên file đích**. Hai file cùng tên ở hai nơi dùng **chung một LNK**: Created giữ lần mở đầu, Modified và đường dẫn cập nhật theo lần mở cuối. Ví dụ CASE01: `winter_whether_advisory.zip.lnk` Created 14:01:23Z (mở trên E:) nhưng đích hiện tại `D:\de\...` (mở từ CD lúc 20:44:18Z).
- Timestamp của chính file .lnk là **timestamp file system** ⇒ mất nếu copy bằng công cụ thông thường (xem mục 7).
- Một số USB tự báo là "Fixed storage media" (LNK của E:\RM#1 trên CASE01) ⇒ không dựa riêng vào DriveType để kết luận ổ ngoài.

**Quan sát thực tế trên CASE01:** 15 LNK; trỏ tới E:\RM#1 (serial 5C754D3E), `\\10.11.11.128\secured_drive`, ổ quang D: (serial E297F1A5, A58AD72A, AE88F176), Desktop (C:, serial CA0C7A48).

---

## 3. Jump Lists

| Mục | Nội dung |
|---|---|
| Vị trí | `...\Recent\AutomaticDestinations\*.automaticDestinations-ms`, `...\Recent\CustomDestinations\*.customDestinations-ms` |
| Tool | JLECmd 2026.10.5 – chạy trên F: (14 file) |
| Thông tin | Danh sách file/thư mục gần đây **theo từng ứng dụng** (AppID), thời điểm entry được cập nhật, đường dẫn đích |

**Chứng minh được:** file được mở bởi **ứng dụng cụ thể** (Excel, XPS Viewer, Explorer…) và đường dẫn tại lúc mở.

**KHÔNG chứng minh được:** file còn tồn tại; nội dung đã xem; số lần mở chính xác.

**Quan sát thực tế trên CASE01:** 31 entry AutomaticDestinations. Đáng chú ý: Excel mở `\\10.11.11.128\secured_drive\...\pricing decision\(secret_project)_pricing_decision.xlsx` (20:26:53Z); `V:\Secret Project Data\final\[secret_project]_final_meeting.pptx` (20:27:33Z) – cùng file với LNK trỏ tới share ⇒ V: là ổ mạng ánh xạ.

---

## 4. Prefetch

| Mục | Nội dung |
|---|---|
| Vị trí | `C:\Windows\Prefetch\*.pf` |
| Tool | PECmd 2026.10.3 – chạy trên F: (95 file) |
| Timestamp | **LastRun** (Win7: 1 mốc; Win8+: tối đa 8); **RunCount**; Created của file .pf ≈ lần chạy đầu + ~10 giây |
| Thông tin khác | Đường dẫn exe, volume, danh sách file/thư mục được nạp trong 10 giây đầu |

**Chứng minh được:** chương trình **đã được thực thi** trên máy, số lần và thời điểm chạy gần nhất.

**KHÔNG chứng minh được:** user nào chạy; chạy thành công hay làm gì (ví dụ CCleaner được mở nhưng theo NIST không làm gì); file nào bị tác động.

**Lưu ý:** Win7 chỉ có 1 LastRun ⇒ dùng Created của .pf để ước lượng lần chạy đầu, nhưng Created là timestamp file system (mất khi copy). Trường hợp chưa giải thích: `GOOGLEDRIVESYNC.EXE` .pf Created 2015-03-25 15:21:40Z sau LastRun 9 giây dù Google Drive đã dùng từ 23/03.

**Quan sát thực tế trên CASE01 (ngày 25/03):** ERASER installer 14:50:14Z, ERASER.EXE (2 lần, cuối 15:13:30Z), CCSETUP504 14:57:56Z, CCLEANER64 (2 lần, cuối 15:15:50Z), UNINST.EXE 15:18:29Z, GOOGLEDRIVESYNC 15:21:31Z, WINWORD 15:24:48Z, XPSRCHVW 15:28:47Z.

---

## 5. Recycle Bin

| Mục | Nội dung |
|---|---|
| Vị trí | `C:\$Recycle.Bin\<SID>\$I*` (metadata: đường dẫn gốc, kích thước, thời điểm xóa), `$R*` (nội dung) |
| Tool | RBCmd 2026.10.1 |

**Chứng minh được:** file bị đưa vào thùng rác bởi user có SID tương ứng, đường dẫn gốc, thời điểm xóa.

**KHÔNG chứng minh được:** xóa vĩnh viễn (Shift+Delete, Empty Recycle Bin, công cụ wipe đều không để lại $I).

**Quan sát thực tế trên CASE01:** 3 thư mục SID (RID 1000, 1001, 1003), mỗi thư mục chỉ có `desktop.ini`; RBCmd: 0 file. Theo NIST user đã Empty Recycle Bin (11:14 EDT 25/03) và dùng Shift+Delete nhiều lần ⇒ **không có dấu vết ≠ không có hành vi**.

---

## 6. Registry bổ trợ (đã dùng / cần dùng)

| Key | Hive | Dùng để |
|---|---|---|
| `Select\Current` | SYSTEM | Xác định ControlSet đang dùng (CASE01: 1) |
| `ControlSet001\Control\TimeZoneInformation` | SYSTEM | Timezone: Eastern Standard Time, Bias 300, ActiveTimeBias 240 (UTC−4) |
| `ControlSet001\Enum\USBSTOR`, `MountedDevices` | SYSTEM | Nhận dạng USB (serial) – **cần làm** để phân biệt RM#1/RM#2 |
| `Software\Microsoft\Windows NT\CurrentVersion\ProfileList` | SOFTWARE | Map SID → user – **cần làm** |
| `...\Explorer\MountPoints2`, `Network\V` | NTUSER.DAT | Ổ mạng ánh xạ (V:) |

---

## 7. Bài học về xử lý artifact

| Vấn đề | Hậu quả | Cách xử lý |
|---|---|---|
| Copy bằng `Copy-Item` | Created/Accessed của .lnk, .pf bị đổi thành thời điểm copy (2026-10-28 03:16:40Z) | Chạy LECmd/JLECmd/PECmd trực tiếp trên ổ mount read-only; hoặc dùng công cụ thu thập giữ timestamp (KAPE, FTK Imager export) |
| Timestamp nằm **trong** artifact (ShellBags, LastRun, MAC đích trong LNK) | Không bị ảnh hưởng khi copy | – |
| Cùng ký tự ổ cho nhiều thiết bị | E: là RM#1 lúc 13:38Z nhưng là RM#2 lúc 13:58Z+ ngày 24/03 | Dùng volume serial (LNK), USBSTOR để phân biệt |
| Ghi log với hậu tố `Z` nhưng là giờ local | Sai múi giờ trong log thu thập lượt 1 | Dùng `(Get-Date).ToUniversalTime()` |
