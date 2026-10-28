# Manual Evidence – CASE01

> Mỗi finding được kiểm chứng thủ công bằng tool GUI độc lập với tool trích xuất (SBECmd).
> Ba mức kết luận: **Observed** (artifact cho thấy trực tiếp) · **Inferred** (suy luận) · **NIST-confirmed** (khớp đáp án chính thức). "Verified" ở đây nghĩa là đã kiểm chứng bằng công cụ GUI độc lập với SBECmd.
> Giờ UTC. Giờ máy nghi phạm = UTC − 4h (EDT, xem `case_notes/timezone.md`).

## Thông tin evidence
- Image: `cfreds_2015_data_leakage_pc.dd`
  - MD5: `A49D1254C873808C58E6F1BCD60B5BDE` – khớp giá trị NIST công bố (leakage-answers.pdf, mục 4.1)
  - SHA-256: `026C143638295DB1FBFA598C5B35BCAC4860BA73EC5DA1CC87B67AFD598BE4E2`
- Mount: FTK Imager, Block Device / Read Only → F:
- Hive dùng (bản copy trong evidence_work):
  - `UsrClass.dat` – SHA-256 `A26FE02DA57E6C84A911EDF9DD39021ECF200D66D168841331DAE0BE9DD2F1B7`
  - `NTUSER.DAT` – SHA-256 `2190B57E2908D36F835589CC530C8C471EA48952F8EDEA70CC91488D9B5D1F64`
- Timezone máy evidence: Eastern Standard Time, ActiveTimeBias 240 (UTC−4, EDT)

---

### CASE01-F001 – Duyệt "Secret Project Data" trên network share \\10.11.11.128\secured_drive
- **Trạng thái:** VERIFIED (2026-10-28)
- **Artifact:** ShellBags (2 hive độc lập)
- **Tool trích xuất:** SBECmd 2026.10.2 → `output/sbecmd/20261028_103708/Deduplicated.csv`
- **Tool kiểm chứng:** ShellBags Explorer 2026.10.1, time zone UTC

| # | Hive | Thư mục | Key path | MRU | First interacted | Last interacted | Key LastWrite | Khớp SBECmd |
|---|---|---|---|---|---|---|---|---|
| 1 | UsrClass.dat | `...\secured_drive\Secret Project Data\design` | `BagMRU\8\0\0\2` (value 0) | 5 | 2015-03-23 20:24:12.943 | – | 2015-03-23 20:28:17.754 | ✅ |
| 2 | UsrClass.dat | `...\secured_drive\Secret Project Data\pricing decision` | `BagMRU\8\0\0\2` (value 1) | 0 | 2015-03-23 20:24:15.814 | 2015-03-23 20:28:17.754 | 2015-03-23 20:28:17.754 | ✅ |
| 3 | NTUSER.DAT | `...\secured_drive\Secret Project Data\design` | `BagMRU\0\0\0\2` (value 0) | 5 | 2015-03-23 20:24:14.753 | – | 2015-03-23 20:28:17.769 | ✅ |

- **Target timestamps trong shell item** (cả 3 mục): Created/Modified/Accessed 2015-03-22 14:52:22 – là MAC của thư mục trên share lúc ShellBag được ghi, **không phải** thời điểm truy cập.
- **Diễn giải timestamp:**
  - Key LastWrite 20:28:17 chỉ gắn chắc với mục **MRU 0** (`pricing decision`) ⇒ đó là thư mục được mở cuối cùng trong `Secret Project Data`.
  - `design` (MRU 5): thời điểm đáng tin là First interacted 20:24:12 (UsrClass) / 20:24:14 (NTUSER).
  - Hai hive lệch nhau ~2 giây cho cùng thư mục – bình thường vì hai hive được ghi độc lập.
- **Artifact bổ trợ:** LNK `(secret_project)_pricing_decision.xlsx.lnk` Created 2015-03-23 20:26:53Z (NetworkPath `\\10.11.11.128\SECURED_DRIVE`), `[secret_project]_final_meeting.pptx.lnk` Created 20:27:33Z.
- **Observed:** user `informant` đã duyệt cây thư mục `Secret Project Data` trên share `\\10.11.11.128\secured_drive` trong khoảng 20:24–20:28Z ngày 2015-03-23 (16:24–16:28 EDT); 2 file trên share được mở qua Shell.
- **Inferred:** user rà soát dữ liệu mật trước khi thu thập/rò rỉ.
- **NIST-confirmed:** 16:23 EDT kết nối share (RunMRU 16:23:28 – khớp ShellBag `10.11.11.128` 20:23:28Z), 16:24 EDT duyệt thư mục, 16:28 EDT copy `pricing_decision.xlsx` và `final_meeting.pptx` về `S data`.
- **Giới hạn:** ShellBags không cho biết file nào trong thư mục được mở hay sao chép; phần "mở file" dựa vào LNK.
- **Event đã đổi sang verified trong `shellbags_findings.csv`:** CASE01-SB0031–0033, 0056–0061, 0131–0133, 0150, 0157–0159.
- **Ảnh:** `case_notes/img/F001_design.png`, `case_notes/img/F001_pricing_decision.png`, `case_notes/img/F001_design_NTUSER.png`

---

### CASE01-F004 – File winter_whether_advisory.zip trên thiết bị ngoài E:
- **Trạng thái:** VERIFIED phần ShellBags (2026-10-28). Phần nhận dạng thiết bị (USBSTOR) chưa kiểm.
- **Artifact:** ShellBags (UsrClass.dat) + LNK
- **Tool trích xuất:** SBECmd 2026.10.2; LECmd 2026.10.3 (chạy trên F:)
- **Tool kiểm chứng:** ShellBags Explorer 2026.10.1, time zone UTC

| # | Mục | Key path | MRU | Shell type | First interacted | Last interacted | Key LastWrite | Khớp SBECmd |
|---|---|---|---|---|---|---|---|---|
| 1 | `This PC\E:\Secret Project Data\design\winter_whether_advisory.zip` | `BagMRU\1\0\1\4` (value 0) | 0 | File | – | 2015-03-24 14:01:29.766 | 2015-03-24 14:01:29.766 | ✅ |
| 2 | `...\winter_whether_advisory.zip\ppt` | (con của #1) | 0 | Zip file contents | 2015-03-24 14:01:32 | 2015-03-24 14:01:32 | 2015-03-24 14:01:32 | ✅ |

- **Target timestamps của file zip (shell item):** Created 2015-03-24 13:59:38 · Modified 2014-12-16 16:10:26 · Accessed 2015-03-24 04:00:00
- **Diễn giải:**
  - Created mới hơn Modified ~3 tháng ⇒ dấu hiệu file được **sao chép** vào E: (copy giữ Modified, đặt Created mới) lúc ~13:59:38Z, ~2 phút trước khi mở. *(Inferred)*
  - Accessed đúng 04:00:00 UTC = 00:00 EDT ⇒ chỉ có **ngày** truy cập, đặc trưng của hệ thống file **FAT** ⇒ E: nhiều khả năng là USB định dạng FAT; đồng thời xác nhận thêm timezone UTC−4. *(Inferred)*
- **LNK bổ trợ:** `winter_whether_advisory.zip.lnk` Created 2015-03-24 14:01:23Z (lần mở đầu, khớp ShellBag 14:01:29Z), Modified 20:44:18Z trỏ tới `D:\de\...` (xem F005).
- **Observed:** file `winter_whether_advisory.zip` tồn tại trên E:\Secret Project Data\design và user đã mở xem bên trong (thư mục `ppt`) lúc 14:01Z ngày 24/03 (10:01 EDT).
- **Giới hạn:** ShellBags không chứng minh nội dung zip là dữ liệu mật; tên file "winter_whether_advisory" có thể là ngụy trang – cần kiểm tra nội dung.
- **NIST-confirmed (EDT+4=UTC):** 09:58 EDT cắm USB **RM#2**, 09:59 EDT copy toàn bộ `Secret Project Data` sang RM#2 (khớp Created 13:59:38Z), 10:00 EDT mở `winter_whether_advisory.zip` – NIST ghi JumpList 10:01:23 và ShellBag 10:01:29 EDT, khớp chính xác LNK 14:01:23Z và ShellBag 14:01:29Z. ⇒ Ổ E: tại thời điểm này là **RM#2**, không phải RM#1 (RM#1 cũng từng là E: lúc 13:38Z).
- **Event đã verified:** CASE01-SB0001, 0171, 0254, 0266–0270.
- **Ảnh:** `case_notes/img/F004_zip_E.png`

---

### CASE01-F005 – Thư mục "de" trong khu chờ ghi đĩa CD (CDBurn) trên D:
- **Trạng thái:** VERIFIED (2026-10-28)
- **Artifact:** ShellBags (UsrClass.dat) + LNK
- **Tool kiểm chứng:** ShellBags Explorer 2026.10.1, time zone UTC

| Mục | Key path | MRU | Shell type | First interacted | Last interacted | Key LastWrite | Khớp SBECmd |
|---|---|---|---|---|---|---|---|
| `This PC\D:\de` | `BagMRU\1\3` (value 0) | 0 | **CDBurn** | 2015-03-24 19:54:35.357 | 2015-03-24 20:44:13.155 | 2015-03-24 20:44:13.155 | ✅ |

- **Target timestamps:** Created/Modified/Accessed 2015-03-24 19:47:48 ⇒ thư mục `de` được tạo trong khu chờ ghi đĩa lúc 19:47:48Z, mở lần đầu ~7 phút sau.
- **Cùng nhánh D: (CDBurn):** `tr`, `prog`, `prop`, `pd` – thấy trong cây ShellBags Explorer.
- **LNK bổ trợ:** `winter_whether_advisory.zip.lnk` Modified 2015-03-24 20:44:18Z, target `D:\de\winter_whether_advisory.zip`, ổ quang (Optical disc), volume serial E297F1A5 – 5 giây sau Last interacted của `D:\de`.
- **Observed:** user đưa thư mục `de` (và `tr`, `prog`, `prop`, `pd`) vào khu chờ ghi đĩa của ổ D: và mở file zip từ `D:\de` lúc 20:44Z (16:44 EDT).
- **Inferred:** `de/pd/prog/prop/tr` = viết tắt của design / pricing decision / progress / proposal / technical review ⇒ dữ liệu mật được đổi tên rồi ghi ra CD.
- **NIST-confirmed:** 16:40 EDT (20:40Z) user đổi tên design→de, pricing decision→pd, progress→prog, proposal→prop, technical review→tr; 16:41 EDT ghi CD-R; 16:44 EDT kiểm tra nội dung đĩa (khớp LNK 20:44:18Z).
- **Chưa giải thích:** First interacted của `D:\de` (19:54:35Z = 15:54 EDT) sớm hơn mốc đổi tên của NIST ~46 phút, rơi vào giai đoạn NIST mô tả là "tập ghi đĩa với file vô nghĩa" (15:40–16:35 EDT). Có thể thư mục `de` đã được tạo trong lần tập; NIST cũng lưu ý timestamp ShellBag có thể không chính xác.
- **Event đã verified:** CASE01-SB0282–0284, 0309, 0330, 0331.
- **Ảnh:** `case_notes/img/F005_de_CDBurn.png`

---
