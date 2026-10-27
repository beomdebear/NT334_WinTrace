# WinTrace – Event Correlation Rules Draft

## 1. Mục tiêu

Thiết kế tập quy tắc xác định những sự kiện forensic có khả năng liên quan với nhau, hỗ trợ điều tra viên tái dựng hoạt động trên hệ thống Windows.

Kết quả correlation là các candidate findings cần kiểm chứng. Không tự động xem chúng là kết luận chắc chắn.

## 2. R01 – Temporal Proximity

**Mục tiêu:** Xác định những sự kiện có timestamp gần nhau.

**Điều kiện:**
- Các timestamp phải có thể so sánh trên cùng cơ sở thời gian.
- Timestamp type của từng event phải được xác định.
- Khoảng cách thời gian nằm trong một cửa sổ điều tra được cấu hình.

**Đầu ra:** Danh sách các event pairs có quan hệ gần nhau về thời gian.

**Giới hạn:** Temporal proximity không chứng minh quan hệ nhân quả.

## 3. R02 – Object Association

**Mục tiêu:** Nhận diện những event liên quan cùng một file, thư mục hoặc đối tượng.

**Điều kiện:**
- Có dữ liệu object path hoặc định danh đối tượng phù hợp.
- Đường dẫn được chuẩn hóa khi có đủ thông tin.
- Phân biệt exact path match và parent–child relationship.

**Đầu ra:** Các nhóm sự kiện có liên quan đến cùng đối tượng.

**Giới hạn:** Hai đường dẫn có tên giống nhau trên những volume khác nhau có thể là các đối tượng khác nhau.

## 4. R03 – Cross-Artifact Support

**Mục tiêu:** Tìm những nguồn evidence khác nhau có khả năng hỗ trợ cùng giả thuyết.

**Điều kiện:**
- Có tối thiểu hai nguồn artifact phù hợp.
- Các artifact có ý nghĩa forensic bổ trợ nhau.
- Không chỉ dựa vào việc trùng timestamp.

**Đầu ra:** Nhóm supporting events và thông tin nguồn.

**Giới hạn:** Hai event có thể bắt nguồn từ cùng một hoạt động ghi dữ liệu, không nhất thiết là hai nguồn chứng cứ độc lập.

## 5. R04 – Program–File Association

**Mục tiêu:** Xác định các dấu vết thực thi chương trình và tương tác file có khả năng liên quan.

**Điều kiện:**
- Có execution evidence từ Prefetch hoặc artifact phù hợp.
- Có file reference evidence như LNK hoặc application artifacts.
- Ứng dụng và loại file có quan hệ hợp lý.
- Timestamp semantics cho phép đánh giá mối liên hệ thời gian.

**Đầu ra:** Program–file association candidates.

**Giới hạn:** Chương trình được thực thi không đồng nghĩa đã mở file được tham chiếu.

## 6. R05 – Deletion Context

**Mục tiêu:** Tìm những sự kiện liên quan đến file hoặc thư mục trước khi xuất hiện deletion evidence.

**Điều kiện:**
- Có artifact hỗ trợ hoạt động xóa, chẳng hạn Recycle Bin metadata.
- Có những event tham chiếu cùng file hoặc đối tượng liên quan.
- Thứ tự thời gian đã được kiểm tra.

**Đầu ra:** Candidate activity sequence xung quanh dấu vết xóa file.

**Giới hạn:** Không khẳng định động cơ xóa file hoặc danh tính người thực hiện nếu thiếu bằng chứng.

## 7. Kiểm chứng correlation findings

Với mỗi candidate finding, điều tra viên cần kiểm tra:
- Evidence nguồn.
- Timestamp semantics.
- Mối liên hệ đối tượng.
- Những giả thuyết thay thế.
- Sự phù hợp với ground truth nếu có.

## 8. Hướng triển khai tuần 2

Correlation engine nhận các event đã được chuẩn hóa từ pipeline của Nam theo schema thống nhất với Quyên.

Module thực hiện việc lựa chọn event candidates, áp dụng các rule, nhóm sự kiện và xuất thông tin phục vụ kiểm chứng.

Thi không chịu trách nhiệm thiết kế lại evidence schema hoặc thay đổi dữ liệu nguồn.
