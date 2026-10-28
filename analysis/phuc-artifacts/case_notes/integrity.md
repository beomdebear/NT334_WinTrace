# Integrity – CASE01

## File tải (MD5 – so với giá trị công bố)
```
Algorithm Hash                             Path                                                  
--------- ----                             ----                                                  
MD5       C327DB25292296AB10C2670B94EF28B5 D:\UIT\HK5\PCKTS\LT\cfreds_2015_data_leakage_pc.7z.001
MD5       8A5185144C7D38C111D5505E3018BA73 D:\UIT\HK5\PCKTS\LT\cfreds_2015_data_leakage_pc.7z.002
MD5       E155D374D77643A9FF44A664D628BF87 D:\UIT\HK5\PCKTS\LT\cfreds_2015_data_leakage_pc.7z.003
```
Giá trị công bố: .001 c327db25292296ab10c2670b94ef28b5 · .002 8a5185144c7d38c111d5505e3018ba73 · .003 e155d374d77643a9ff44a664d628bf87 → **khớp cả 3**.

## Ảnh đĩa cfreds_2015_data_leakage_pc.dd
- MD5: `A49D1254C873808C58E6F1BCD60B5BDE` – khớp NIST (leakage-answers.pdf, mục 4.1)
- SHA-256: `026C143638295DB1FBFA598C5B35BCAC4860BA73EC5DA1CC87B67AFD598BE4E2`

## Hive dùng phân tích (bản copy trong evidence_work)
- UsrClass.dat – SHA-256 `A26FE02DA57E6C84A911EDF9DD39021ECF200D66D168841331DAE0BE9DD2F1B7`
- NTUSER.DAT – SHA-256 `2190B57E2908D36F835589CC530C8C471EA48952F8EDEA70CC91488D9B5D1F64`
- Hai lượt thu thập độc lập cho hash giống hệt nhau.

## Output tool đưa vào repo
- `tool_output/sbecmd/Deduplicated.csv` – SHA-256 `1bad7daaf24e87efccd37d19902b142f08b6bbe06aedeee8979e20b6ffcd770b` (output gốc SBECmd 2026.10.2, không chỉnh sửa; là đích của cột evidence_reference `Deduplicated.csv:L<n>`)
