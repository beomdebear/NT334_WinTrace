# Artifact-to-Activity Mapping

## 1. Mục tiêu

Xác định mối liên hệ giữa các Windows forensic artifacts và bốn nhóm hoạt động được nghiên cứu trong WinTrace: Program Execution, File Knowledge, File Opening và File Deletion.

Việc mapping phải dựa trên cơ chế tạo artifact và ý nghĩa forensic của dữ liệu, không đơn thuần dựa vào sự tồn tại của một file hoặc timestamp.

## 2. Program Execution

**Artifact chính:** Windows Prefetch.

Prefetch có thể lưu các thông tin liên quan đến thực thi chương trình, gồm tên executable, run count và những execution timestamps được định dạng Prefetch tương ứng hỗ trợ.

Khi tìm thấy artifact Prefetch hợp lệ, điều tra viên có thể sử dụng nó làm bằng chứng hỗ trợ việc một chương trình đã được thực thi.

**Giới hạn:** Prefetch có thể bị vô hiệu hóa, không tồn tại hoặc bị ghi đè. Prefetch cũng không tự chứng minh một người dùng cụ thể đã thực thi chương trình.

**Artifact bổ trợ:** Windows Event Logs, Amcache và các nguồn execution artifacts khác khi có sẵn.

## 3. File Knowledge

**Artifact chính:** ShellBags, LNK và các Recent artifacts.

ShellBags lưu thông tin về thư mục được Windows Shell ghi nhận, có thể hỗ trợ xác định lịch sử tương tác hoặc điều hướng thư mục.

LNK có thể lưu đường dẫn và metadata của một đối tượng được tham chiếu.

**Giới hạn:** Sự tồn tại của một đường dẫn trong artifact không chứng minh người dùng đã đọc nội dung file.

## 4. File Opening

**Artifact có thể sử dụng:** LNK, Jump Lists và application-specific artifacts.

Một số artifact có thể hỗ trợ điều tra lịch sử người dùng tương tác với tài liệu hoặc ứng dụng.

Khi phân tích cần phân biệt thời điểm tạo shortcut, timestamp của target file và các dấu vết do ứng dụng tạo.

**Giới hạn:** Một LNK file không tự chứng minh file target đã được mở tại timestamp được hiển thị. Kết luận phải dựa trên cơ chế tạo artifact và các bằng chứng bổ trợ.

## 5. File Deletion

**Artifact chính:** Recycle Bin metadata.

Trên các phiên bản Windows phù hợp, các file `$I` có thể chứa đường dẫn gốc, kích thước và timestamp liên quan đến việc đưa file vào Recycle Bin; `$R` có thể chứa nội dung file tương ứng.

**Artifact bổ trợ:** NTFS metadata và USN Journal nếu có.

**Giới hạn:** Việc xóa vĩnh viễn hoặc xóa bằng những phương thức khác có thể không tạo ra cùng loại Recycle Bin artifacts.

## 6. Nguyên tắc diễn giải

- Không đồng nhất artifact existence với user activity.
- Không đồng nhất mọi timestamp với action time.
- Không suy luận file opening từ folder navigation.
- Không xác định người thực hiện nếu artifact không hỗ trợ user attribution.
- Không tự coi việc thiếu artifact là bằng chứng hoạt động không xảy ra.
- Mỗi nhận định phải ghi rõ evidence và giới hạn.

## 7. Ứng dụng trong WinTrace

Artifact-to-Activity Mapping được sử dụng để xác định những nguồn evidence phù hợp cho từng loại investigation hypothesis.

Bảng mapping là tài liệu nghiên cứu phục vụ xây dựng correlation rules, không phải tập hợp các luật kết luận tự động.
