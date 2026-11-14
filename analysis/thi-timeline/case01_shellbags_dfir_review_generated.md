# WinTrace – CASE01 ShellBags Correlation Review (Week 2)

## 1. Phạm vi, dữ liệu

- Input: `results/case01_shellbags_events.csv` (383 dòng event).
- Nhóm đường dẫn theo chuỗi: **91**; không đồng nghĩa số lượng ShellItem duy nhất hoặc lượt mở thư mục.
- Số event ID lặp: **0**; cảnh báo dữ liệu: **0**.
- Kết quả này là phân tích dữ liệu đầu ra, không phải findings đã được xác minh.

## 2. Phân loại timestamp

| Nhóm ngữ nghĩa | Số event | Cách hiểu |
|---|---:|---|
| TARGET_METADATA | 168 | Metadata của đối tượng được lưu trong ShellItem; không tự chứng minh hoạt động duyệt thư mục tại mốc đó. |
| REGISTRY_UPDATE | 104 | Registry key LastWrite, cần MRUListEx và ngữ cảnh hive. |
| INFERRED_INTERACTION | 111 | First/Last Interacted do công cụ suy ra, cần xác nhận điều kiện. |
| OTHER_OR_UNKNOWN | 0 | Chưa xác định ngữ nghĩa, cần kiểm tra. |

## 3. Ngữ cảnh đối tượng nổi bật

| Vùng điều tra | Đường dẫn ShellBags | Số timestamp | Giới hạn |
|---|---|---:|---|
| Network share | `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Past Projects` | 11 | Chỉ chứng minh sự hiện diện của dấu vết ShellBags; cần đối chiếu LNK, Jump Lists, source hive/volume và ground truth. |
| Secret project folders | `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\Secret Project Data\design` | 10 | Chỉ chứng minh sự hiện diện của dấu vết ShellBags; cần đối chiếu LNK, Jump Lists, source hive/volume và ground truth. |
| E drive entry | `Desktop\This PC\E:\RM#1\Secret Project Data\design` | 6 | Chỉ chứng minh sự hiện diện của dấu vết ShellBags; cần đối chiếu LNK, Jump Lists, source hive/volume và ground truth. |

## 4. Đánh giá prototype correlation (số liệu từ lần chạy trước)

- 383 events → 6.063 candidate pairs: 4.482 `R02`, 1.581 `R01+R02`.
- Bộ lọc rà soát ban đầu còn 452 cặp cùng full-path trong 5 phút; đây không phải 452 user activities.
- R02: quan hệ path chỉ nên tạo **object context**, không mặc định là finding hành vi.
- R01: chỉ so sánh timestamp có ngữ nghĩa tương thích; gần thời gian không chứng minh quan hệ nhân quả.
- R03: ưu tiên bằng chứng bổ trợ thực sự từ LNK/Prefetch/EVTX, không chỉ khác nhãn artifact.
- R04/R05: đòi hỏi evidence thực thi/xóa riêng và thứ tự thời gian có nghĩa; ShellBags-only chưa đủ.

## 5. Proposed correlation policy (đề xuất, CHƯA sửa engine)

1. Giữ nguyên tất cả timestamp event gốc, kể cả khi cùng path.
2. Phân tách `object_context` và `activity_candidate`. Cặp ShellBags/ShellBags không tự là user action finding.
3. Phân biệt timestamp `TARGET_METADATA`, `REGISTRY_UPDATE`, `INFERRED_INTERACTION`.
4. Chỉ dùng cross-artifact correlation khi case_id khớp, timezone/semantics hợp lệ, có provenance.
5. Các kết luận `copied`, `opened file`, `deleted` phải có nguồn chứng cứ phù hợp, đối chiếu Phúc/Quyên.

## 6. Phụ thuộc & hành động tiếp theo

- Quyên đang sửa `src/correlation.py` và `tests/test_correlation.py`: không chỉnh hai file này khi chưa thống nhất.
- Trao đổi quy tắc ở mục 5 với Quyên; nhận dữ liệu CASE01 LNK/Prefetch/Jump Lists từ Phúc/Nam.
- Khi mã nguồn được bàn giao, viết tests cho cross-artifact và false correlations; kiểm tra trên cùng case_id.
- Tài liệu cần được review thủ công trước khi commit vì ngữ cảnh nguồn có thể chưa đủ.

## 7. Tham khảo

- Microsoft Security, *Leveraging Windows Internals for Forensic Investigation* (ShellBags Guide).
- artifacts.help, *Registry – Shellbags*: https://artefacts.help/windows_registry_shellbags.html
