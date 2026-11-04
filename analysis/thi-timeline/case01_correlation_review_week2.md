# WinTrace — Review of CASE01 First-pass Correlation (Week 2)

## 1. Phạm vi và đầu vào

Dữ liệu được đánh giá là `results/case01_candidates_review.csv` — tập **452 cặp** được lọc trước đó từ **6.063** candidate pairs của 383 timestamp events ShellBags. Điều kiện lọc cũ: R01 + R02, cùng chuỗi đường dẫn chuẩn hóa cơ bản, chênh lệch thời gian không quá 5 phút. Đây là **bộ dữ liệu rà soát**, không phải output đã được validation hoặc danh sách hành vi thực tế.

## 2. Thống kê xác minh từ CSV

| Chỉ số | Số lượng |
|---|---:|
| Candidate pairs được rà soát | 452 |
| Chuỗi đường dẫn phân biệt trong bộ rà soát | 70 |
| Cặp có hai timestamp bằng nhau | 275 |
| Cặp gồm hai mốc ShellItem Target metadata | 231 |
| Cặp có ít nhất một BagMRU timestamp | 221 |

Chú ý: `275` cặp cùng thời điểm không biểu thị `275` lượt người dùng mở thư mục. Không dùng tỷ lệ trên làm precision/recall vì chưa có nhãn ground truth ở mức cặp.

## 3. Minh họa từ các event thực tế

### Network share — thư mục design

- Object path: `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Secret Project Data\design`
- Ví dụ event pair: `CASE01-SB0031` ↔ `CASE01-SB0032`
- Thời điểm UTC: `2015-03-22T14:52:22+00:00` ↔ `2015-03-22T14:52:22+00:00`
- Timestamp labels: `ShellItem Target Created` / `ShellItem Target Modified`
- Diễn giải giới hạn: Các mốc `ShellItem Target Created/Modified/Accessed` hỗ trợ mô tả metadata thư mục trong dấu vết ShellBags. Không suy ra file cụ thể được mở/sao chép.

### Thiết bị/volume E: — RM#1

- Object path: `Desktop\This PC\E:\RM#1`
- Ví dụ event pair: `CASE01-SB0007` ↔ `CASE01-SB0010`
- Thời điểm UTC: `2015-02-15T21:51:38+00:00` ↔ `2015-02-15T21:52:08+00:00`
- Timestamp labels: `ShellItem Target Modified` / `ShellItem Target Accessed`
- Diễn giải giới hạn: Các mốc liên quan đến đường dẫn trên E:; cần kiểm tra volume/device identity và các artifact bổ trợ trước khi liên kết với network share hoặc kết luận thao tác sao chép.

### Control Panel — Create New Account

- Object path: `Desktop\ControlPanelHome\All Control Panel Items\User Accounts\Manage Accounts\Create New Account`
- Ví dụ event pair: `CASE01-SB0098` ↔ `CASE01-SB0101`
- Thời điểm UTC: `2015-03-22T15:51:54+00:00` ↔ `2015-03-22T15:53:05+00:00`
- Timestamp labels: `BagMRU First Interacted` / `BagMRU Key Last Write`
- Diễn giải giới hạn: BagMRU First Interacted và Key LastWrite là dấu vết về giao diện/registry; không tự chứng minh tài khoản đã được tạo thành công.

## 4. Đánh giá hạn chế của engine hiện tại

- **R01** chỉ đo độ gần về thời gian. Mốc thời gian khác ngữ nghĩa không thể tự động xem là cùng một hoạt động.
- **R02** chỉ chứng minh quan hệ giữa các *path strings* hoặc object references mà thuật toán nhận diện; quan hệ cha-con/trùng tên không nhất thiết là cùng file hay cùng phiên làm việc.
- Những cặp ShellBags ↔ ShellBags, nhất là mốc `ShellItem Target *`, nên được phân loại **object context**. Chưa đủ căn cứ để xuất độc lập thành *user activity finding*.
- Không có dữ liệu LNK/Prefetch/EVTX/Jumplists trong tập CSV đầu vào này để kiểm tra giá trị của **R03–R05**.
- File CSV sau lọc không đủ để xác nhận các cặp timestamp cùng một ShellItem record; cần trở về output gốc, hive, BagMRU key/slot, event ID và evidence reference.

## 5. Đề xuất cải tiến cho giai đoạn tích hợp với Quyên

1. Giữ nguyên toàn bộ raw events và evidence references.
2. Phân tầng `object_context` và `activity_candidate` thay vì coi mỗi R01/R02 match là finding.
3. Trước khi ghép cặp, giới hạn cùng `case_id`, kiểm tra timestamp semantics, path/volume identity và provenance.
4. Không sử dụng R02-only thành investigation finding. Không mặc định `ShellItem Target Accessed` là thao tác mở thư mục.
5. Với R03–R05, dùng bằng chứng độc lập phù hợp và ghi rõ mức độ khẳng định; không tự đặt validation status = verified.
6. Viết unit tests âm tính về metadata-only pairs, same filename khác thư mục, hai case khác nhau và quan hệ UNC/drive chưa xác minh.

## 6. Phần việc chưa hoàn tất

- Kiểm chứng metadata từ các hàng trong `case01_shellbags_timestamp_audit.csv` và `case01_shellbags_path_context.csv`.
- Đối chiếu case với Phúc; cần nguồn LNK, Prefetch và Jump Lists được chuẩn hóa từ CASE01.
- Tích hợp policy vào `src/correlation.py` và bổ sung kiểm thử.

**Trạng thái:** Bản DFIR analytical review phục vụ phát triển tuần 2; chưa phải kết luận điều tra hoặc báo cáo validation.
