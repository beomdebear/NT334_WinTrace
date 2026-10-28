# CASE01 – Candidate Findings (bản nháp từ output tool, CHƯA kiểm chứng thủ công)

> Nguồn: SBECmd 2026.10.2 (`output/sbecmd/20261028_103708/Deduplicated.csv`, 109 ShellBags),
> LECmd 2026.10.3 và PECmd 2026.10.3 chạy **trực tiếp trên ổ mount read-only F:** (`output/lecmd/fromF/`, `output/pecmd/fromF/`) để giữ timestamp file system gốc.
> Với LNK: Created ≈ lần mở đầu, Modified ≈ lần mở gần nhất. Với Prefetch (Win7): Created của .pf ≈ lần chạy đầu + ~10 giây.
> Giờ: UTC (giờ máy nghi phạm = UTC − 4h, EDT). Tất cả finding ở trạng thái **unverified** cho đến khi Phúc kiểm tay (Ngày 6).
> "Observed" = artifact cho thấy trực tiếp. "Inferred" = suy luận, cần artifact khác xác nhận.

---

## CASE01-F001 – Duyệt thư mục "Secret Project Data" trên network share
- **Thời gian:** 2015-03-23 20:23:28Z → 20:28:17Z (16:23–16:28 EDT)
- **ShellBags (cả NTUSER.DAT và UsrClass.dat):** `Computers and Devices\10.11.11.128\secured_drive\` → `Common Data`, `Past Projects`, `Secret Project Data\{design, final, pricing decision, progress, proposal, technical review}`. FirstInteracted của các thư mục con nối tiếp nhau trong khoảng 20:24:12–20:24:35Z.
- **LNK bổ trợ:** `(secret_project)_pricing_decision.xlsx.lnk` (Modified 20:26:53Z), `[secret_project]_final_meeting.pptx.lnk` (20:27:33Z), NetworkPath `\\10.11.11.128\secured_drive`.
- **Observed:** user duyệt các thư mục dự án mật trên share; LNK cho thấy 2 file trên share được mở qua Shell.
- **Inferred:** user rà soát toàn bộ cấu trúc dữ liệu mật trước khi thu thập.
- **Confidence:** high (2 hive + LNK độc lập).

## CASE01-F002 – Ổ V: chứa "Secret Project Data\final"
- **Thời gian:** 2015-03-23 20:27:24Z – 20:27:29Z
- **ShellBags:** `This PC\V:\Secret Project Data\final`
- **Observed:** thư mục cùng tên trên ổ V: được duyệt, ngay giữa phiên duyệt share ở F001.
- **Jump List (JLECmd):** `V:\Secret Project Data\final\[secret_project]_final_meeting.pptx` (20:27:33Z) – trong khi LNK cùng tên file trỏ tới `\\10.11.11.128\secured_drive` ⇒ V: là ổ mạng ánh xạ tới share.
- **Đối chiếu NIST:** 16:26 EDT map V: tới `\\10.11.11.128\secured_drive`, 16:29 EDT unmap ⇒ **xác nhận**.
- **Confidence:** high.

## CASE01-F003 – Bản sao dữ liệu mật trên Desktop ("S data")
- **Thời gian:** 2015-03-24 13:40:13Z → 13:57:40Z (09:40–09:57 EDT)
- **ShellBags (UsrClass.dat):** `Desktop\S data\Secret Project Data\{Common Data, Past Projects, design, final, pricing decision, progress, proposal, technical review}` và một lớp lồng `Secret Project Data\Secret Project Data\...`.
- **Observed:** cấu trúc thư mục giống hệt share ở F001 xuất hiện trên Desktop của user và được duyệt.
- **Inferred:** dữ liệu đã được sao chép từ share về máy (ShellBags KHÔNG chứng minh hành vi copy).
- **Đối chiếu NIST:** 24/03 09:40–09:56 EDT copy và đổi tên 20 file vào `S data\Secret Project Data`; **10:07 EDT xóa cả thư mục `S data` bằng Shift+Delete** ⇒ ShellBags vẫn lưu dấu thư mục đã bị xóa – minh họa giá trị của ShellBags.
- **Confidence:** medium.

## CASE01-F004 – Dữ liệu mật trên thiết bị lưu trữ ngoài (E:)
- **ShellBags:** `E:\RM#1\Secret Project Data` (13:38:31Z), `E:\RM#1\Secret Project Data\design` (13:38:52Z); `E:\Secret Project Data\{design, pricing decision, progress, proposal, technical review}` (FirstInteracted 14:01:11–14:01:17Z, ngày 2015-03-24); duyệt vào bên trong `E:\Secret Project Data\design\winter_whether_advisory.zip` (14:01:29–14:01:32Z).
- **LNK:** `E:\RM#1\Secret Project Data\proposal\[secret_project]_proposal.docx` (Created/Modified 2015-03-23 18:37:20Z) và `...\design\[secret_project]_design_concept.ppt` (Created/Modified 18:38:21Z) – Volume serial **5C754D3E**. Created = Modified ⇒ mỗi file chỉ được mở 1 lần qua Shell.
- **LNK `winter_whether_advisory.zip.lnk`:** Created 2015-03-24 14:01:23Z (khớp ShellBag `E:\Secret Project Data\design\winter_whether_advisory.zip` 14:01:29Z) – lần mở đầu tiên là trên E:.
- **Observed:** cấu trúc "Secret Project Data" tồn tại trên E: và được duyệt; 2 file trên E: được mở qua Shell.
- **Inferred:** E: là thiết bị ngoài (USB) dùng để chứa/chuyển dữ liệu mật. Cần đối chiếu serial 5C754D3E với SYSTEM `Enum\USBSTOR`, SOFTWARE `Windows Portable Devices` / `EMDMgmt`. Lưu ý: LNK ghi DriveType "Fixed" – một số USB tự báo là ổ cố định.
- **Đối chiếu NIST (EDT+4=UTC):** RM#1 được cắm 2 lần: 23/03 14:31 EDT (mở file 14:37–14:39 EDT = 18:37–18:39Z, khớp LNK) và 24/03 09:38 EDT (=13:38Z, khớp ShellBag `E:\RM#1`). Lúc 09:58 EDT (13:58Z) một USB **khác – RM#2** – được cắm, cũng nhận ký tự **E:**; `E:\Secret Project Data\...` lúc 14:00–14:01Z là **RM#2**.
- **Bài học:** cùng ký tự ổ E: nhưng là 2 thiết bị khác nhau ⇒ ShellBags/LNK chỉ ghi ký tự ổ, phải dùng volume serial / USBSTOR để phân biệt thiết bị.
- **Confidence:** medium.

## CASE01-F005 – Chuẩn bị ghi đĩa CD (CD Burning) với tên thư mục viết tắt
- **Thời gian:** 2015-03-24 19:54:35Z → 20:44:18Z (15:54–16:44 EDT)
- **ShellBags:** ShellType **CDBurn** cho `D:\de`, `D:\pd`, `D:\prog`, `D:\prop`, `D:\tr`; duyệt bên trong `D:\de\winter_whether_advisory.zip\ppt\slides`.
- **LNK:** cùng file `winter_whether_advisory.zip.lnk`, Modified 20:44:18Z, nay trỏ tới `D:\de\winter_whether_advisory.zip` – Optical disc, serial **E297F1A5**. Cùng tên file nên Windows cập nhật lại một LNK: lần mở đầu trên E: (14:01Z), lần mở cuối từ đĩa CD (20:44Z) ⇒ file đã đi từ USB sang CD.
- `CD Drive.lnk`: Created 20:47:22Z, serial A58AD72A.
- **Observed:** thư mục được đưa vào khu vực chờ ghi đĩa của ổ quang D:.
- **Inferred → XÁC NHẬN bởi NIST:** 16:40 EDT (20:40Z) user đổi tên design→de, pricing decision→pd, progress→prog, proposal→prop, technical review→tr rồi ghi CD-R; 16:44 EDT kiểm tra nội dung đĩa (khớp LNK 20:44:18Z).
- **Điểm lệch:** ShellBag `D:\de` First interacted 19:54:35Z (15:54 EDT) sớm hơn mốc đổi tên của NIST (16:40 EDT); NIST ghi 15:40–16:35 EDT là giai đoạn "tập ghi đĩa" với file vô nghĩa. Cần giải thích – NIST cũng lưu ý timestamp ShellBag có thể không chính xác.
- **Ghi chú:** 21:01Z cùng ngày, ổ D: là một đĩa khác (serial AE88F176) chứa Penguins.jpg, Koala.jpg, Tulips.jpg (ảnh mẫu Windows) – có thể là đĩa "mồi".
- **Confidence:** medium (suy luận đổi tên cần thêm bằng chứng).

## CASE01-F006 – Thư mục Google Drive
- **ShellBags:** `Users Files\Google Drive` – FirstInteracted 2015-03-23 20:05:34Z, LastInteracted 2015-03-25 15:20:59Z.
- **Prefetch:** GOOGLEDRIVESYNC.EXE run count 2, LastRun 2015-03-25 15:21:31Z; file .pf Created 15:21:40Z.
- **Đối chiếu NIST:** 11:22 EDT (15:22Z) ngày 25/03 user mở Google Drive để ngắt kết nối tài khoản và đăng xuất ⇒ khớp LastRun.
- **Điểm chưa giải thích:** Google Drive đã dùng từ 23/03 (ShellBag 20:05Z) nhưng .pf chỉ được tạo 25/03 15:21:40Z. Giả thuyết ban đầu "gỡ/cài lại Google Drive" **bị bác bỏ** (NIST: lần gỡ lúc 15:18Z là CCleaner và iCloud). Nguyên nhân .pf mới còn để mở – ghi vào Hạn chế.
- **Observed:** Google Drive được cài/chạy và thư mục đồng bộ được duyệt.
- **Inferred:** kênh rò rỉ qua cloud có thể đã được dùng – cần xem nội dung thư mục, log sync.
- **Confidence:** medium.

## CASE01-F007 – Công cụ xóa dấu vết (anti-forensics)
- **Prefetch (ngày 2015-03-25):**
  | Chương trình | Lần chạy đầu (≈ .pf Created − 10s) | LastRun | RunCount |
  |---|---|---|---|
  | ERASER 6.2.0.2962.EXE (installer) | ~14:50:14Z | 14:50:14Z | 1 |
  | ERASER.EXE | ~15:12:28Z | 15:13:30Z | 2 |
  | CCSETUP504.EXE (installer) | ~14:57:57Z | 14:57:56Z | 1 |
  | CCLEANER64.EXE | ~14:58:27Z | 15:15:50Z | 2 |
- **ShellBags:** `Desktop\Recycle Bin` FirstInteracted 2015-03-25 14:14:17Z; `Programs and Features` 15:19:20Z (cùng lúc UNINST.EXE / MSIEXEC – theo NIST là gỡ CCleaner và iCloud).
- **RBCmd:** thùng rác hiện không có $I nào.
- **ShellBags liên quan:** `Desktop\temp` (FirstInteracted 2015-03-24 19:52:13Z).
- **Đối chiếu NIST (EDT → UTC):** 11:13 EDT dùng Eraser xóa `Desktop\temp` (khớp ERASER.EXE LastRun 15:13:30Z); 11:14 EDT dọn Recycle Bin; 11:15 EDT mở CCleaner nhưng không làm gì (khớp 15:15:50Z); 11:18 EDT gỡ CCleaner và iCloud (khớp UNINST.EXE 15:18:29Z).
- **Observed:** Eraser và CCleaner được cài và thực thi; thùng rác trống; thư mục Desktop\temp từng tồn tại.
- **Inferred:** user cố tình xóa dữ liệu/dấu vết trước khi nghỉ việc. Prefetch không cho biết Eraser xóa file nào.
- **Confidence:** high cho "đã thực thi"; medium cho mục đích.

## CASE01-F008 – Thư xin nghỉ việc
- **LNK:** `Resignation_Letter_(Iaman_Informant).docx` – Created **2015-03-24 18:48:40Z** (mở lần đầu), Modified 2015-03-25 15:29:08Z (mở lần cuối); `.xps` – Created/Modified 2015-03-25 15:28:33Z.
- **Prefetch:** WINWORD.EXE lần chạy đầu ~2015-03-24 18:32Z, LastRun 2015-03-25 15:24:48Z (3 lần); XPSRCHVW.EXE 2015-03-25 15:28:47Z.
- **Observed:** thư xin nghỉ việc được mở lần đầu chiều 24/03 và mở lại, xuất XPS ngay sau chuỗi xóa dấu vết ở F007 (25/03).
- **Confidence:** high.

---

## Chuỗi sự kiện sơ bộ (gửi Thi để correlate)
| UTC | EDT | Sự kiện | Finding |
|---|---|---|---|
| 2015-03-23 18:37 | 14:37 | Mở file proposal/design trên E:\RM#1 | F004 |
| 2015-03-23 20:05 | 16:05 | Lần đầu duyệt thư mục Google Drive | F006 |
| 2015-03-23 20:23–20:28 | 16:23–16:28 | Duyệt share \\10.11.11.128\secured_drive, mở file pricing/final | F001, F002 |
| 2015-03-24 13:38–14:01 | 09:38–10:01 | Duyệt "S data" trên Desktop và "Secret Project Data" trên E:; mở winter_whether_advisory.zip trên E: | F003, F004 |
| 2015-03-24 18:48 | 14:48 | Mở thư xin nghỉ việc lần đầu | F008 |
| 2015-03-24 19:54–20:44 | 15:54–16:44 | Chuẩn bị ghi CD với thư mục viết tắt | F005 |
| 2015-03-25 14:50–15:15 | 10:50–11:15 | Cài & chạy Eraser, CCleaner | F007 |
| 2015-03-25 15:21 | 11:21 | Google Drive sync chạy lần cuối | F006 |
| 2015-03-25 15:24–15:29 | 11:24–11:29 | Soạn thư xin nghỉ việc | F008 |

## Việc cần làm để nâng các finding lên "verified"
1. Mở UsrClass.dat / NTUSER.DAT trong ShellBags Explorer, đối chiếu từng path + thời gian ở trên.
2. Kiểm tra USBSTOR / MountPoints2 để xác định E: và V:.
3. Đối chiếu với đáp án NIST (quy giờ đáp án về UTC).
4. ~~Chạy lại LECmd/JLECmd/PECmd trên ổ F:~~ – ĐÃ LÀM (output `fromF`). Ghi vào Hạn chế: bản copy bằng Copy-Item mất Created/Accessed của LNK và .pf; output trong `20261028_103708` cho LNK/Prefetch không dùng cho timeline.
