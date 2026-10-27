# Super Timeline Fundamentals

## 1. Tổng quan

Trong điều tra số trên hệ điều hành Windows, các hoạt động của người dùng và hệ thống có thể tạo ra nhiều dấu vết tại những nguồn dữ liệu khác nhau, được gọi là forensic artifacts.

Một số nguồn quan trọng bao gồm Windows Registry, Prefetch, LNK, Windows Event Logs và NTFS metadata. Mỗi nguồn chứa những thông tin có giá trị pháp chứng riêng, nhưng không phản ánh toàn bộ hoạt động của hệ thống.

Super Timeline là phương pháp tập hợp những sự kiện có thông tin thời gian từ nhiều nguồn forensic artifacts, sau đó tổ chức chúng trong một hệ thống thời gian thống nhất nhằm hỗ trợ điều tra viên phân tích trình tự hoạt động.

Trong dự án WinTrace, Plaso được sử dụng để trích xuất và tạo timeline từ forensic evidence. Hệ thống tiếp tục phân tích các sự kiện, xác định các mối liên hệ và hỗ trợ tái dựng hoạt động dựa trên bằng chứng.

## 2. Các khái niệm cơ bản

**Forensic Artifact:** Dữ liệu hoặc dấu vết có thể chứa thông tin về hoạt động trước đó của hệ thống, ứng dụng hoặc người dùng.

**Forensic Event:** Một bản ghi được trích xuất từ artifact, bao gồm thông tin sự kiện, thời gian và nguồn dữ liệu.

**Super Timeline:** Tập hợp các sự kiện từ nhiều artifact, được chuẩn hóa và tổ chức theo thời gian để hỗ trợ điều tra.

**Investigation Finding:** Nhận định được xây dựng sau khi phân tích một hoặc nhiều sự kiện và đánh giá bằng chứng hỗ trợ.

## 3. Quy trình Super Timeline Analysis

Quy trình phân tích bao gồm:

1. Evidence Acquisition: Thu thập dữ liệu điều tra và bảo toàn tính toàn vẹn.
2. Artifact Extraction: Trích xuất dữ liệu từ các forensic artifacts.
3. Event Parsing: Chuyển dữ liệu thành các sự kiện có thể phân tích.
4. Timeline Creation: Chuẩn hóa và tổ chức sự kiện theo thời gian.
5. Timeline Filtering: Xác định những sự kiện liên quan đến phạm vi điều tra.
6. Event Correlation: Phân tích quan hệ giữa các sự kiện từ nhiều nguồn.
7. Evidence Validation: Kiểm chứng nhận định bằng dữ liệu và nguồn chứng cứ.
8. Activity Reconstruction: Xây dựng trình tự hoạt động có thể được chứng minh hoặc hỗ trợ từ evidence.

## 4. Giá trị của Super Timeline

Super Timeline giúp điều tra viên:

- Tổng hợp nhiều loại artifact trong cùng một khung thời gian.
- Xác định các sự kiện xảy ra trước và sau một mốc đáng chú ý.
- Nhận diện những mối liên hệ giữa hoạt động file, chương trình và hệ thống.
- Thu hẹp phạm vi điều tra bằng cách lọc theo thời gian và đối tượng.
- Tái dựng hoạt động với các bằng chứng có thể truy vết.

## 5. Giới hạn của Super Timeline

Super Timeline không phải bản ghi đầy đủ mọi hành động của người dùng.

Thời gian được trích xuất có thể phản ánh việc thay đổi metadata, hoạt động ứng dụng hoặc cập nhật Registry thay vì trực tiếp phản ánh một hành động cụ thể.

Ngoài ra, artifact có thể không được tạo, bị ghi đè, bị thiếu hoặc chứa timestamp không đủ chính xác.

Vì vậy, sự xuất hiện của nhiều sự kiện gần nhau về thời gian chỉ nên được xem là cơ sở để hình thành giả thuyết. Quan hệ nhân quả cần được kiểm chứng bằng các nguồn evidence phù hợp.

## 6. Vai trò của Timeline Reconstruction trong WinTrace

Module Timeline Reconstruction & Correlation có trách nhiệm phân tích các sự kiện đã được trích xuất, xác định những mối liên hệ có giá trị forensic và tạo ra các candidate findings.

Module không thay thế quá trình kiểm chứng của điều tra viên. Kết quả phải giữ được thông tin về nguồn chứng cứ, điều kiện liên kết và giới hạn của từng nhận định.
