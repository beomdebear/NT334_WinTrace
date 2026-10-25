# WinTrace – Super Timeline Creation and Analysis

> **Môn học:** NT334 – Pháp chứng kỹ thuật số (Digital Forensics)  
> **Đồ án:** Phân tích và Xây dựng Super Timeline trên hệ điều hành Windows  

---

## Giới thiệu tổng quan
**WinTrace** là giải pháp phân tích pháp chứng kỹ thuật số tập trung vào việc tạo và phân tích **Super Timeline** từ nhiều nguồn bằng chứng độc lập trên Windows (Prefetch, ShellBags, LNK, Windows Event Logs EVTX, Recycle Bin).

Dự án áp dụng công cụ trích xuất công nghiệp **Plaso (`log2timeline` / `psort`)**, chuẩn hóa sự kiện theo **Event Schema** thống nhất, thực hiện **Cross-Validation** (đối chiếu chéo giữa các nguồn) và áp dụng **Correlation Rules (R01 - R05)** để tái dựng chuỗi hành vi của người dùng và hệ thống với độ tin cậy pháp chứng cao.