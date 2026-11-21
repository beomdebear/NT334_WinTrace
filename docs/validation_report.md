# Validation Report – Tuần 2 – CASE01

**Dự án:** WinTrace – Automated Windows Forensic Artifact Extraction & Super Timeline Analysis
**Người thực hiện:** Quyên – Validation & Visualization Engineer
**Ngày:** 2026-11-08
**Trạng thái:** Hoàn thành tuần 2 (Tích hợp UI, Report Export và Cross-Validation)

> **Các trạng thái kiểm chứng (Validation Status) dùng trong báo cáo:**
> - **Verified** – Khớp với Ground Truth (đáp án NIST) hoặc được đối chiếu chéo thành công qua các nguồn artifact độc lập.
> - **Unverified** – Dữ liệu trích xuất tự động bằng Plaso/WinTrace, chưa có bằng chứng đối soát.
> - **Disputed** – Xuất hiện mâu thuẫn thời gian (Temporal Anomaly) hoặc xung đột logic.
> - **Synthetic** – Dữ liệu mô phỏng kịch bản (Scenario Alpha), không dùng làm chứng cứ.

> Quy ước giờ: mọi timestamp ở **UTC** (hậu tố Z hoặc +00:00). Giờ máy nghi phạm = UTC − 4h (EDT).

---

## 1. Mục tiêu và Phạm vi kiểm chứng

Báo cáo này đánh giá tính toàn vẹn của **Super Timeline** và độ tin cậy của **Correlation Findings** do module của Thi sinh ra trong Tuần 2.
- **Dataset:** NIST CFReDS – Data Leakage Case (CASE01) và kịch bản Ground Truth mô phỏng (Scenario Alpha).
- **Công cụ kiểm chứng:** Module `cross_validation.py` (tự động) và bộ Unit Tests (`test_validation.py`).
- **Phạm vi:** Kiểm tra các giả thuyết H1 (Navigation), H2 (Execution), và H3/H4 (Deletion Lifecycle).

## 2. Kết quả đối soát chéo (Cross-Validation Results)

Dựa trên thiết kế tại `validation_design.md`, module Validation đã chạy kiểm thử trên toàn bộ tập sự kiện đã chuẩn hóa. Kết quả tổng thể: **VERIFIED (Không phát hiện mâu thuẫn logic)**.

### 2.1. Giả thuyết H1: User Navigation (Điều hướng thư mục trước khi mở file)
- **Cơ chế:** Đối chiếu thời gian duyệt thư mục từ `ShellBags` với thời gian truy cập file đích từ `LNK` / `Prefetch`.
- **Kết quả:** `PASS`. 
- **Chi tiết:** Các sự kiện điều hướng (ShellBags MRU) luôn xảy ra *trước* hoặc *cùng lúc* (time delta $\ge$ 0) với sự kiện tương tác file bên trong thư mục đó. Không có trường hợp file bị tác động trước khi thư mục chứa nó được hệ thống ghi nhận.

### 2.2. Giả thuyết H2: Document Execution (Thực thi tài liệu)
- **Cơ chế:** Đối chiếu file `LNK` (Shortcut) với tiến trình thực thi tương ứng trong `Prefetch` (vd: `.docx` đi kèm `WINWORD.EXE`).
- **Kết quả:** `PASS`.
- **Chi tiết:** Các tài liệu văn phòng khi được mở qua Shell (sinh ra LNK) đều có sự kiện Prefetch của ứng dụng tương ứng chạy trong khoảng thời gian rất sát ($\le 10$ phút). Sự tương quan này củng cố mạnh mẽ độ tin cậy (Confidence Level: HIGH) cho các finding liên quan đến việc mở tài liệu mật.

### 2.3. Giả thuyết H3 & H4: File Deletion Lifecycle (Chu kỳ xóa file)
- **Cơ chế:** Kiểm tra tính hợp lý của dòng thời gian trước khi file bị đưa vào `Recycle Bin` ($I Metadata).
- **Kết quả:** `PASS` (0 Contradictions).
- **Chi tiết:** Không phát hiện bất kỳ sự kiện nào có timestamp truy cập/sửa đổi file lại diễn ra *sau* thời điểm file đó đã bị xóa vào thùng rác. Sự kiện EVTX 4663 (Access Mask: `DELETE`) luôn đi trước timestamp của file `$I`.

## 3. Thống kê Giao diện và Báo cáo (UI & Report Export)

Module giao diện (Streamlit) và xuất báo cáo đã được hoàn thiện và tích hợp thành công với SQLite Database (`storage.py`).

| Tính năng | Trạng thái | Đánh giá / Ghi chú |
|---|---|---|
| **Timeline Database Connection** | Hoạt động | Đọc thành công `schema_version v2`, hiển thị đầy đủ `timestamp_type` và `evidence_reference`. |
| **Targeted Filtering** | Hoạt động | Lọc chính xác theo Artifact Type, Keyword và Time Range. Không bị crash khi query null. |
| **Evidence Detail Viewer** | Hoạt động | Parse thành công `extra_attributes` (JSON), giữ nguyên chuỗi Chain of Custody để điều tra viên truy vết. |
| **Correlation Findings Viewer** | Hoạt động | Map chính xác Finding ID với cặp sự kiện (Event A, Event B) và hiển thị các rule đã khớp (R01-R05). |
| **HTML/CSV Report Export** | Hoạt động | Định dạng báo cáo rõ ràng, highlight các finding có `Confidence: HIGH`. Dữ liệu xuất ra giữ nguyên Provenance. |

## 4. Hạn chế và Ghi chú điều tra (Investigation Notes)
- **Độ phân giải thời gian (Timestamp Precision):** Báo cáo ghi nhận một số sự kiện từ `ShellBags` (FAT time) có độ lệch $\pm 2$ giây. Hệ thống Correlation đã tự động điều chỉnh time window để bù trừ, UI đã hiển thị cảnh báo loại timestamp (ví dụ: `ShellItem_FolderModified`) để điều tra viên lưu ý khi phân tích sâu.
- **Dữ liệu Unverified:** Các candidate finding có điểm số ở mức MEDIUM vẫn cần điều tra viên kiểm chứng thủ công (verify) trước khi đưa ra kết luận cuối cùng.

## 5. Kết luận
Phân hệ Validation và Visualization (v2) đã hoàn thành xuất sắc các mục tiêu của Tuần 2. Giao diện ổn định, sẵn sàng cho việc tải các dataset lớn hơn và phục vụ kịch bản diễn tập (Demo) cho Tuần 3.