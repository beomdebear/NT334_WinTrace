# WinTrace – Validation Design & Cross-Validation Framework

## 1. Mục tiêu và Phạm vi
Tài liệu này xác định phương pháp luận kiểm chứng (**Validation Design**) và thiết kế ma trận đối soát chéo (**Cross-Validation Framework**) cho dự án **WinTrace**.

Trong điều tra số, một nhận định (finding) chỉ được xem là có giá trị bằng chứng khi:
1. Có thể tái lập (Reproducible) với dữ liệu gốc.
2. Được kiểm chứng chéo bởi tối thiểu hai nguồn artifact độc lập hoặc phù hợp với cơ chế kỹ thuật đã được công nhận.
3. Phân biệt rõ giữa *tương quan thống kê / thời gian* (correlation) và *quan hệ nhân quả* (causality).

---

## 2. Thiết kế Ground Truth (Kịch bản chuẩn Scenario Alpha)

Để đánh giá chính xác hiệu năng của hệ thống WinTrace, nhóm xây dựng bộ dữ liệu kiểm chứng với chuỗi hành vi thực tế có mốc thời gian đã biết trước (Ground Truth Timeline):

| Mốc thời gian (UTC) | Hành vi thực tế (Ground Truth Activity) | Artifacts kỳ vọng sinh ra | Tiêu chuẩn phát hiện thành công |
|---|---|---|---|
| **02:05:12** | Người dùng Alice đăng nhập tài khoản | EVTX Security ID 4624 (LogonType 2) | Phát hiện phiên đăng nhập tương tác của Alice |
| **02:10:00** | Alice mở Windows Explorer duyệt vào thư mục `C:\Users\Alice\Documents\Project` | ShellBags (`UsrClass.dat`) | ShellBags ghi nhận `BagMRU` path match và MRU time |
| **02:12:00** | Alice nhấp đúp mở file `confidential_report.docx` | LNK file trong thư mục `Recent` | Shortcut LNK trỏ đúng target path và có timestamp ~02:12 |
| **02:14:00** | Ứng dụng Microsoft Word (`WINWORD.EXE`) nạp và hiển thị tài liệu | Prefetch `WINWORD.EXE.pf`, EVTX 4688 | Prefetch ghi nhận Last Run ~02:14, loaded files có `confidential_report.docx` |
| **02:18:30** | Alice nhấn `Delete` để chuyển tài liệu vào Recycle Bin | Recycle Bin `$I39F1AA.docx`, `$R39F1AA.docx` | `$I` file lưu đúng đường dẫn gốc và deletion time 02:18:30 |

---

## 3. Ma trận Đối soát chéo (Cross-Validation Matrix)

Hệ thống WinTrace triển khai ma trận kiểm chứng chéo để tự động đánh giá độ tin cậy của các giả thuyết:

```
+-----------------------------------------------------------------------------------------+
|                                  CROSS-VALIDATION MATRIX                                |
+------------------------+-----------------------------+----------------------------------+
| Giả thuyết điều tra    | Bằng chứng sơ cấp (Primary) | Bằng chứng đối chiếu (Secondary) |
+------------------------+-----------------------------+----------------------------------+
| H1: User Navigation    | ShellBags MRU path          | Parent path trong LNK / MFT      |
| H2: File Execution/Open| LNK Target File Path        | Prefetch Loaded Files & Run Time |
| H3: User Attribution   | User SID in Recycle Bin     | EVTX 4624 Interactive Logon      |
| H4: File Deletion      | Recycle Bin $I Metadata     | EVTX 4663 Access Mask / USN Log  |
+------------------------+-----------------------------+----------------------------------+
```

### 3.1. Quy tắc tính điểm tin cậy (Confidence Scoring)
Mỗi candidate finding sau khi chạy correlation rules sẽ được gắn điểm tin cậy từ 0 đến 100:
- **Baseline (+20đ):** Thỏa mãn quy tắc gần nhau về thời gian (R01 - Temporal Proximity $\le 5$ phút).
- **Object Match (+30đ):** Thỏa mãn cùng đối tượng đường dẫn hoặc quan hệ cha-con (R02 - Object Association).
- **Multi-Source Corroboration (+30đ):** Bằng chứng xuất phát từ $\ge 2$ loại artifact khác nhau (R03 - Cross-Artifact Support).
- **Execution & File Binding (+20đ):** Ứng dụng thực thi có tham chiếu trực tiếp đến file được mở (R04 - Program-File Association).
- **Xác định chủ thể (Attribution Bonus +10đ):** Cùng định danh User SID / Username giữa các sự kiện.

**Xếp hạng độ tin cậy:**
- $\ge 80$ điểm: **HIGH CONFIDENCE** (Bằng chứng vững chắc, đủ điều kiện đưa vào báo cáo chính).
- $50 - 79$ điểm: **MEDIUM CONFIDENCE** (Cần kiểm tra bổ sung log phụ).
- $< 50$ điểm: **LOW / CANDIDATE ONLY** (Chỉ là gợi ý sơ bộ, tiềm ẩn false positive).

---

## 4. Tiêu chí Đánh giá Hiệu năng (Validation Metrics)

Hệ thống được đánh giá theo 4 chỉ số chuẩn:
1. **Precision (Độ chuẩn xác):**
   $$\text{Precision} = \frac{TP}{TP + FP}$$
   Tỷ lệ các liên kết sự kiện được engine tìm ra là chính xác theo Ground Truth.
2. **Recall (Độ bao phủ):**
   $$\text{Recall} = \frac{TP}{TP + FN}$$
   Tỷ lệ các sự kiện trong Ground Truth được engine phát hiện và liên kết đầy đủ.
3. **False Positive Rate (Tỷ lệ dương tính giả - FPR):** Các liên kết ngẫu nhiên do trùng thời điểm nhưng không liên quan bản chất.
4. **False Negative Rate (Tỷ lệ âm tính giả - FNR):** Các hành vi thực tế bị bỏ sót do ngưỡng cửa sổ thời gian hoặc lệch tên file.

---

## 5. Phương pháp Kiểm thử (Testing Protocol)
1. **Unit Testing:** Kiểm tra tính độc lập của từng parser, tính toàn vẹn của schema validation (`tests/test_schema.py`).
2. **Rule Verification:** Kiểm tra từng rule R01 - R05 độc lập với các cặp sự kiện biên (`tests/test_correlation.py`).
3. **Cross-Validation Testing:** Kiểm tra tính năng đối soát chéo và phát hiện mâu thuẫn thời gian (`tests/test_cross_validation.py`).
4. **End-to-End Pipeline Run:** Nạp file Super Timeline đầy đủ, chạy lọc, tương quan và so khớp với kết quả kỳ vọng trong `results/`.
