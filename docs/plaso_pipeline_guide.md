# WinTrace – Hướng dẫn Nghiên cứu & Vận hành Plaso Pipeline

Tài liệu này tổng hợp toàn bộ phần việc kỹ thuật của pipeline xử lý dữ liệu Plaso trong Tuần 1:
1. **Setup Plaso / Python**
2. **Khảo sát Plaso Input**
3. **Nghiên cứu Plaso Parsers & Plugins**
4. **Quy trình chạy Plaso & Export CSV/JSON**
5. **Data Normalization & Kiến trúc Pipeline**

---

## 1. Setup Plaso & Môi trường Python

Plaso là bộ công cụ mã nguồn mở viết bằng Python phục vụ trích xuất forensic timeline từ nhiều nguồn chứng cứ số.

### 1.1. Các thành phần chính của Plaso
- `log2timeline.py`: Công cụ trích xuất chính, đọc bằng chứng (disk image, file, directory) và nạp vào file lưu trữ trung gian `.plaso` (SQLite hoặc Zip-based storage).
- `pinfo.py`: Kiểm tra thông tin metadata, danh sách parser đã chạy, thống kê số lượng sự kiện trong file `.plaso`.
- `psort.py`: Công cụ xử lý hậu kỳ, lọc sự kiện, sắp xếp theo thời gian và kết xuất (export) ra các định dạng đích (`dynamic`, `csv`, `json_line`, `elastic`).

### 1.2. Hướng dẫn cài đặt trên Windows
Trên Windows 10/11, Plaso có thể cài đặt theo 3 phương thức:

#### Cách 1: Docker (Khuyên dùng - Ổn định và không xung đột thư viện C)
```powershell
# Kéo image Plaso chính thức từ Docker Hub
docker pull log2timeline/plaso

# Kiểm tra hoạt động
docker run -v ${PWD}:/data log2timeline/plaso log2timeline --version
docker run -v ${PWD}:/data log2timeline/plaso psort --version
```

#### Cách 2: WSL2 (Windows Subsystem for Linux)
```bash
# Trong Ubuntu WSL2:
sudo add-apt-repository ppa:gift/stable
sudo apt-get update
sudo apt-get install plaso-tools
```

#### Cách 3: Python Virtual Environment (Windows Standalone)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install plaso
```

---

## 2. Khảo sát Plaso Input (Các định dạng đầu vào)

Plaso hỗ trợ khả năng phân tích cực kỳ đa dạng:

| Loại Input | Định dạng hỗ trợ | Trường hợp sử dụng |
|---|---|---|
| **Raw Disk Image** | `.dd`, `.raw`, `.img` | Ảnh đĩa toàn vẹn thu thập từ ổ cứng vật lý |
| **Expert Witness Format** | `.E01`, `.Ex01` | Chuẩn ảnh đĩa forensic tiêu chuẩn của EnCase / FTK Imager có hash checksum |
| **Virtual Disk Images** | `.vmdk` (VMware), `.vhd`/`.vhdx` (Hyper-V) | Máy ảo hoặc bản sao lưu snapshot |
| **Volume Shadow Copies** | VSS Snapshots qua flag `--vss-stores` | Khai thác các phiên bản cũ của file hệ thống trên Windows |
| **Targeted Directory (Triage)** | Thư mục chứa artifacts (`C:\Triage_Data\`) | Phân tích nhanh (Fast triage) khi chỉ thu thập các file artifact trọng điểm |
| **Individual Forensic Files** | File `.pf`, `.lnk`, `UsrClass.dat`, `.evtx` | Kiểm thử hoặc phân tích mẫu chứng cứ đơn lẻ |

---

## 3. Nghiên cứu Plaso Parsers & Plugins trọng tâm cho Windows

Plaso chứa hàng trăm parser. Khi phân tích hệ thống Windows, để tối ưu tốc độ và tránh nhiễu dữ liệu, pipeline cần cấu hình lọc danh sách parser cụ thể qua cờ `--parsers`:

| Artifact | Parser / Plugin trong Plaso | Thuộc tính trích xuất chính |
|---|---|---|
| **ShellBags** | `winreg/bagmru`, `winreg/mrulistex` | Cây thư mục `BagMRU`, `MRUListEx`, View settings, first/last interaction timestamps |
| **Prefetch** | `prefetch` | Execution count, hash, timestamps (tối đa 8 mốc), loaded files & DLL paths |
| **Shortcut LNK** | `lnk` | Target path, target timestamps, drive type, volume serial, NetBIOS name, MAC address |
| **Event Logs** | `winevtx` (với Windows Vista trở lên) | Event ID, Provider, Channel, Computer, User SID, Event Data |
| **Recycle Bin** | `recycle_bin`, `recycle_bin_info2` | Original file path, deletion timestamp, original file size, index header |
| **NTFS File System** | `mft`, `usnjrnl` | $STANDARD_INFORMATION, $FILE_NAME, MACB timestamps, sequence numbers |

Cú pháp bộ lọc parser khuyến nghị:
```bash
--parsers "prefetch,lnk,winreg,recycle_bin,winevtx"
```

---

## 4. Chạy Plaso & Export CSV/JSON

### Bước 1: Trích xuất bằng chứng vào file storage `.plaso`
```bash
# Chạy với thư mục chứng cứ đã thu thập
log2timeline.py --parsers "prefetch,lnk,winreg,recycle_bin,winevtx" storage.plaso evidence/scenario_wintrace_wk1/
```

### Bước 2: Kiểm tra file storage
```bash
pinfo.py storage.plaso
```

### Bước 3: Export ra CSV và JSON Lines
```bash
# Xuất dạng dynamic CSV (Plaso psort standard)
psort.py -o dynamic -w results/plaso_raw_output.csv storage.plaso

# Xuất dạng JSON Lines (mỗi dòng là một JSON event record)
psort.py -o json_line -w results/plaso_raw_output.jsonl storage.plaso
```

---

## 5. Quy chuẩn Chuẩn hóa Dữ liệu (Data Normalization)

Đầu ra của Plaso chứa nhiều trường mang tính nội bộ (internal timestamp epoch microsecond, parser internal identifier). Pipeline của Nam chịu trách nhiệm:

```
+---------------------------+        +--------------------------+        +----------------------------+
| Plaso Output (CSV / JSON) | -----> |    WinTrace Normalizer   | -----> | Standardized ForensicEvent |
| (Microseconds, raw fields)|        | (src/normalizer.py)      |        | (docs/event_schema.md)     |
+---------------------------+        +--------------------------+        +----------------------------+
                                                                                       │
                                                                                       v
                                                                         +----------------------------+
                                                                         | Correlation & Validation   |
                                                                         +----------------------------+
```

### Bảng ánh xạ trường chuẩn hóa:
1. `datetime` / `timestamp`: Chuyển đổi từ microsecond epoch hoặc UTC string sang ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SS+00:00`).
2. `source` + `data_type`: Ánh xạ thành tên chuẩn hóa: `ShellBags`, `Prefetch`, `LNK`, `RecycleBin`, `EVTX`.
3. `target_path`: Làm sạch, thay dấu `/` thành `\` và chuẩn hóa đường dẫn Windows.
4. `message`: Làm sạch các ký tự xuống dòng thừa, định dạng lại thông tin quan trọng.
5. `extra_attributes`: Đóng gói các thuộc tính riêng (VD: `run_count`, `volume_serial`, `access_mask`).
