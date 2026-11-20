# WinTrace / Thi — Week 3 CASE01 evidence-grounded correlation review

**Ngày chuẩn bị:** 2026-11-20  
**Người phụ trách:** Thi (timeline/correlation)  
**Dữ liệu:** NIST CFReDS Data Leakage CASE01 (không phải scenario Alice 2026)  
**Trạng thái:** `REVIEW PENDING PHÚC` — chưa coi là ba findings `VERIFIED` do engine sinh ra.  
**Đi kèm:** `week3_findings_validation.csv` và `tests/test_case01_week3_evidence.py`.

## 1. Phạm vi và chuẩn kết luận

Đây là **3 hồ sơ ứng viên C1/C2/C5 có evidence thực tế trong repo** được lựa chọn từ `analysis/phuc-artifacts/correlation_evidence_notes.md`. Không được đồng nhất ID `CASE01-C1/C2/C5` trong bảng của Thi với ID `FIND-*` tự sinh của `CorrelationEngine`. Non-ShellBags được tham chiếu bằng **file CSV + dòng công cụ**, chưa được cấp event ID thống nhất từ pipeline. Không tự tạo event ID để hợp thức hóa kết quả.

Phân loại ở đây: `review_pending_phuc` = có tài liệu/bản ghi hỗ trợ, nhưng còn cần Phúc kiểm tra độc lập. `validation_status=unverified` là nhãn an toàn cho **finding/candidate**, **không thay đổi** trạng thái `verified` của một ShellBag event đã được xác nhận ở trường riêng của event. Không suy diễn high confidence hoặc NIST-confirmed từ việc test nguồn dữ liệu đạt.

### Dữ liệu gốc, tham chiếu

- [Phúc → Thi: Correlation Evidence Notes](https://github.com/beomdebear/NT334_WinTrace/blob/dev/analysis/phuc-artifacts/correlation_evidence_notes.md): mục 2, 3, 4.
- [Phúc: Artifact Validation Week 2](https://github.com/beomdebear/NT334_WinTrace/blob/dev/analysis/phuc-artifacts/artifact_validation_week2.md): mục 4–6.
- [383 ShellBags events](https://github.com/beomdebear/NT334_WinTrace/blob/dev/results/case01_shellbags_events.csv): dùng **một lần**, không import thêm `shellbags_findings.csv`.
- [SBECmd Deduplicated.csv](https://github.com/beomdebear/NT334_WinTrace/blob/dev/analysis/phuc-artifacts/tool_output/sbecmd/Deduplicated.csv)
- [LECmd Output from F:](https://github.com/beomdebear/NT334_WinTrace/blob/dev/analysis/phuc-artifacts/tool_output/lecmd/LECmd_Output_fromF.csv)
- [JLECmd AutomaticDestinations from F:](https://github.com/beomdebear/NT334_WinTrace/blob/dev/analysis/phuc-artifacts/tool_output/jlecmd/AutomaticDestinations_fromF.csv)
- [PECmd Output from F:](https://github.com/beomdebear/NT334_WinTrace/blob/dev/analysis/phuc-artifacts/tool_output/pecmd/PECmd_Output_fromF.csv)
- [PECmd timeline from F:](https://github.com/beomdebear/NT334_WinTrace/blob/dev/analysis/phuc-artifacts/tool_output/pecmd/PECmd_Output_Timeline_fromF.csv)
- [Registry USB/network CSV](https://github.com/beomdebear/NT334_WinTrace/blob/dev/analysis/phuc-artifacts/tool_output/registry/registry_usb_network.csv)
- [Time-scoped volume map](https://github.com/beomdebear/NT334_WinTrace/blob/dev/analysis/phuc-artifacts/volume_map_case01.csv)

**Forensic constraint:** Chỉ dùng tool outputs `*_fromF.csv` tạo từ ổ mount read-only. Phúc đã phát hiện bản xử lý trên *file copy* bị timestamps file-system năm 2026; không nhập bản đó vào CASE01. Timestamps ở bảng dưới ghi UTC, không phải hành động user được chứng minh chỉ từ metadata.

## 2. C1 — Duyệt network share rồi có tài liệu Excel

**Candidate ID:** `CASE01-C1` · **nhãn:** `review_pending_phuc`.

| Mốc UTC 2015-03-23 | Nguồn | Ref | Ngữ nghĩa |
|---|---|---|---|
| 20:24:15 | ShellBags | `CASE01-SB0133` → `Deduplicated.csv:L106` | `ShellBag_FirstInteracted`, `semantic_class=user_interaction`, thư mục `\\10.11.11.128\secured_drive\Secret Project Data\pricing decision`, `validation_status=verified` cho **record ShellBag** |
| 20:26:04 | Registry (NTUSER) | `registry_usb_network.csv`, MountPoints2 `##10.11.11.128#secured_drive` | Ngữ cảnh volume/network share; key LastWrite không tự chứng minh thời điểm connect chính xác |
| 20:26:53 | Excel Jump List | `AutomaticDestinations_fromF.csv:L23` | `AppIdDescription=Microsoft Excel 12`, path kết thúc `(secret_project)_pricing_decision.xlsx` trên UNC share |
| 20:26:53 | LNK | `LECmd_Output_fromF.csv:L2` | Shortcut liên hệ file Excel tương ứng, `SourceCreated=20:26:53` |
| 20:28:17 | ShellBags | `CASE01-SB0158`, cùng `Deduplicated.csv:L106` | `ShellBag_LastInteracted` của cùng thư mục, **SAU** mốc Excel JL — không được khẳng định mốc này xảy ra trước file access |

**Đối chiếu:** `SB0133 → JL L23 = +158 giây`. Thư mục của `SB0133` là parent của file Excel trong Jump List. Candidate rule: R01 gần thời gian, R02 quan hệ thư mục–file, R03 *chỉ khi* tính độc lập về nguồn/cơ chế được xác minh. ShellBag cùng hive/key không phải hai chứng cứ độc lập.

**Kết luận có điều kiện:** Bằng chứng hỗ trợ việc duyệt thư mục `pricing decision` trên network share và xuất hiện dấu vết liên quan file Excel ở thời điểm tiếp theo. Việc file được mở bằng Excel được hỗ trợ bởi Jump List và LNK; cần Phúc xác nhận mức độ kết luận.

**Không kết luận:** file bị *copy*, *exfiltrate*, hay `SB0158` xảy ra trước Excel.

## 3. C2 — V: ↔ UNC cùng network object (temporal alias)

**Candidate ID:** `CASE01-C2` · **nhãn:** `review_pending_phuc`.

| Mốc UTC 2015-03-23 | Nguồn | Ref | Ngữ nghĩa |
|---|---|---|---|
| 20:26:04–20:29:00 | Volume map | `volume_map_case01.csv`, hàng `V:` | `V:` được quy về `\\10.11.11.128\secured_drive` **trong khoảng thời gian này**; thời điểm kết thúc theo NIST |
| 20:27:29 | ShellBags | `CASE01-SB0147`, `Deduplicated.csv:L62` | `ShellBag_LastInteracted` với `V:\Secret Project Data\final` |
| 20:27:29 | ShellBags | `CASE01-SB0148`, **cũng** `Deduplicated.csv:L62` | `ShellBag_FirstInteracted` cho **cùng key và cùng mốc**; không được đếm thành chứng cứ thứ hai |
| 20:27:33 | Jump List | `AutomaticDestinations_fromF.csv:L21` | `V:\Secret Project Data\final\[secret_project]_final_meeting.pptx` |
| 20:27:33 | LNK | `LECmd_Output_fromF.csv:L15` | `NetworkPath=\\10.11.11.128\secured_drive`, `CommonPath=Secret Project Data\final\[secret_project]_final_meeting.pptx` |

**Đối chiếu:** `SB0147 → JL L21 = +4 giây`. Cả Jump List và LNK cùng tên file, tương ứng hai biểu diễn `V:` và UNC, được điều hòa bởi volume map trong đúng time window. Candidate R02 phải hỗ trợ alias (không so mỗi string). Không áp dụng ánh xạ `V:` ngoài thời hạn đã chứng minh.

**Kết luận có điều kiện:** Trong phiên network mapping đó, bản ghi `V:` và bản ghi UNC tương ứng với cùng tên/tuyến đường tài liệu. Đây là thử nghiệm *positive* cho path alias của R02.

**Không kết luận:** `SB0147` + `SB0148` là hai bằng chứng; không khẳng định hành vi sao chép.

## 4. C5 — WINWORD Prefetch + DOCX LNK/Jump List

**Candidate ID:** `CASE01-C5` · **nhãn:** `review_pending_phuc`.

| Mốc UTC 2015-03-25 | Nguồn | Ref | Ngữ nghĩa |
|---|---|---|---|
| 15:24:48 | Prefetch | `PECmd_Output_fromF.csv:L88` và dòng WINWORD trong `PECmd_Output_Timeline_fromF.csv` | `WINWORD.EXE` last-run; Phúc ghi trong báo cáo rằng `FilesLoaded` chứa `RESIGNATION_LETTER_(IAMAN_INFORMANT).DOCX` — **cần đối chiếu lại trực tiếp cột FilesLoaded** |
| 15:29:08 | LNK | `LECmd_Output_fromF.csv:L9` | `SourceModified`, file đích `C:\Users\informant\Desktop\Resignation_Letter_(Iaman_Informant).docx` |
| 15:29:08 | Jump List | `AutomaticDestinations_fromF.csv:L19` | `LastModified`, cùng đường dẫn DOCX; AppId đang là `Unknown AppId` trong dữ liệu, không tự đổi nhãn thành Word AppId |

**Đối chiếu:** Prefetch last-run đến LNK/Jump List = `260 giây` = `4 phút 20 giây`. Candidate R01 + R04 **chỉ khi** kiểm tra rõ `FilesLoaded`, đường dẫn/tên file và giới hạn timestamp; không nên dùng mỗi việc `.docx` đi chung `WINWORD.EXE` làm bằng chứng chốt một hành vi.

**Kết luận có điều kiện:** Có dấu vết Word chạy và các artifact liên quan cùng DOCX trong phiên thời gian. Báo cáo Phúc hỗ trợ việc Word đã nạp file đó, chờ review raw `FilesLoaded`.

**Negative control:** `IEXPLORE.EXE` cũng có filename DOCX trong `FilesLoaded`, nhưng **không** được kết luận IE đã mở tài liệu; tên trong loaded file có thể đến từ hội thoại chọn file hoặc tải lên. Không mặc nhiên chuyển lời ghi `FilesLoaded` thành hành động người dùng.

## 5. Bẫy cần giữ khi review và nối correlation

| Kiểm tra | Tránh lỗi |
|---|---|
| `semantic_class` và `is_user_activity` | `ShellItem_* Created/Modified/Accessed` là metadata file, không phải user event |
| `cross_hive_twin_ids`, `registry_write_burst` | Không cộng thêm chứng cứ hoặc confidence cho cùng một thao tác được ghi lặp |
| `timestamp_precision=fat_date_only` | Không so mốc giờ/phút của trường chỉ lưu ngày |
| `volume_map_case01.csv` | `E:` có thể là nhiều USB khác nhau, `V:` và UNC có thể là cùng share trong một khoảng thời gian |
| `R02/R03/R05` | Ba negative tests trên PR #10 của Thi đang FAIL; **không** tự động gọi generated finding là `VERIFIED` |
| SQLite v2 | Thi chạy thật: `timestamp_type`, `evidence_reference`, `validation_status`, `case_id` đều thành `None` qua round-trip; chờ Nam sửa trước khi kiểm chứng UI/engine dùng DB |
| C5 negative controls | Không gán hoạt động mở DOCX cho IE; không kết luận delete từ chạy Eraser |

## 6. Chạy kiểm tra và điều kiện bàn giao

Từ repo chứa các file `analysis/phuc-artifacts/tool_output` đã merge vào `dev`:

```powershell
python -m pytest -q tests/test_case01_week3_evidence.py -v
```

**Kỳ vọng:** 4 kiểm tra nguồn dữ liệu (`C1`, `C2`, `C5`, `E:` reuse). Đây là kiểm tra nhất quán đầu vào, **chưa** phải test `CorrelationEngine`, **chưa** xác nhận `FilesLoaded`, và không khẳng định kết luận forensic đã được review.

Việc cần Phúc xác nhận trước khi chuyển `review_pending_phuc` thành `supported`:

- [ ] C1: UNC folder `SB0133` và JL L23/LNK L2 thực sự liên quan theo object+time; xác nhận điểm độc lập của JL/LNK.
- [ ] C2: `V:` ↔ UNC hợp lệ ở 20:27:33 UTC và `SB0147`/`SB0148` là cùng key không double-count.
- [ ] C5: kiểm tra trực tiếp `PECmd_Output_fromF.csv:L88` cột `FilesLoaded` chứa DOCX; JL L19 AppId `Unknown AppId` không bị gán sai.
- [ ] Không import bản tool output có SourceCreated/Accessed của file copy 2026 như event CASE01.
- [ ] Sửa sai hoặc bổ sung các source refs nếu tool CSV khác dòng/tên file ở checkout hiện tại.

Việc cần Nam/Quyên trước khi kết quả thành end-to-end finding:

- [ ] `ForensicEvent → SQLite → ForensicEvent` bảo toàn 4 trường v2 và `case_id` đúng.
- [ ] UNC normalizer giữ nguyên tiền tố `\\server\share`; alias `V:` chỉ áp trong khoảng valid time.
- [ ] Tạo event IDs và evidence refs cho LNK/JL/PF từ nguồn thật, không dùng `EVT-*` synthetic Alice.
- [ ] Corr engine R02/R03/R05 xử lý false positives; có phân biệt confidence của candidate và validation status.
- [ ] Chạy engine trên CASE01 merged dataset, trace được `finding_id → event_ids → provenance`.

## 7. Trạng thái trước khi commit

**Phần của Thi đã soạn:** 3 candidate hồ sơ + CSV + 4 bài kiểm tra tính nhất quán nguồn dữ liệu. **Chưa chạy pytest trên checkout thật của người dùng từ môi trường tạo gói**; phải chạy trên máy Thi. Chỉ mở PR tuần 3 sau khi xác nhận tests và đề nghị Phúc review bằng chứng; không merge PR #10 chỉ vì tests synthetic cũ xanh.
