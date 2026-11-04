#!/usr/bin/env python3
"""WinTrace week 2: independent DFIR review of CASE01 ShellBags events.

Place this file at analysis/thi-timeline/analyze_case01_shellbags_week2.py
Run from the repository root: python analysis/thi-timeline/analyze_case01_shellbags_week2.py

Uses only Python's standard library. Does not edit src/ or tests/.
Outputs are analytical aids, NOT validated user-activity findings.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / 'results' / 'case01_shellbags_events.csv'
OUTPUT = ROOT / 'results'


def first_value(row: dict, *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ''


def get_extra(row: dict) -> dict:
    value = row.get('extra_attributes') or ''
    if not value:
        return {}
    try:
        extra = json.loads(value)
        return extra if isinstance(extra, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def kind_of_timestamp(label: str) -> tuple[str, str]:
    v = label.casefold()
    if 'shellitem target' in v or 'shellitem_' in v:
        return ('TARGET_METADATA', 'Thời gian của đối tượng trong ShellItem; không phải thời điểm mở thư mục.')
    if 'bagmru key last write' in v:
        return ('REGISTRY_UPDATE', 'Khóa Registry được cập nhật; cần kiểm tra MRUListEx để liên hệ tương tác.')
    if 'bagmru first interacted' in v or 'bagmru last interacted' in v:
        return ('INFERRED_INTERACTION', 'Mốc tương tác do công cụ suy ra; cần xem điều kiện BagMRU/MRUListEx.')
    return ('OTHER_OR_UNKNOWN', 'Chưa phân loại chắc chắn, cần kiểm tra timestamp semantics.')


def normalize_path_for_grouping(value: str) -> str:
    # Group textually equivalent paths only. Does NOT equate drive letters with UNC or resolve volume identity.
    return value.replace('/', '\\').rstrip('\\').casefold()


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    with path.open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if not INPUT.exists():
        raise SystemExit(f'Khong tim thay {INPUT}. Hay dat script trong analysis/thi-timeline/ va kiem tra CSV CASE01.')

    with INPUT.open('r', encoding='utf-8-sig', newline='') as handle:
        raw_rows = list(csv.DictReader(handle))

    reviewed = []
    errors = []
    seen_ids = Counter()
    for idx, row in enumerate(raw_rows, start=2):
        extra = get_extra(row)
        event_id = first_value(row, 'event_id')
        case_id = first_value(row, 'case_id') or str(extra.get('case_id') or '')
        if (case_id and case_id.upper() != 'CASE01') or (event_id and not event_id.startswith('CASE01-')):
            raise SystemExit(f'Line {idx}: event belongs to another case: event_id={event_id!r}, case_id={case_id!r}')
        if event_id:
            seen_ids[event_id] += 1
        timestamp = first_value(row, 'timestamp_utc', 'timestamp', 'datetime')
        label = first_value(row, 'timestamp_desc', 'timestamp_type') or str(extra.get('timestamp_type') or '')
        path = first_value(row, 'object_path', 'target_path')
        source = first_value(row, 'source_file')
        ref = first_value(row, 'evidence_reference') or str(extra.get('evidence_reference') or '')
        category, interpretation = kind_of_timestamp(label)
        try:
            parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                errors.append(f'Line {idx}: timestamp has no timezone: {timestamp}')
                parsed = None  # Do not infer a timezone
        except ValueError:
            parsed = None
            errors.append(f'Line {idx}: invalid timestamp: {timestamp}')
        if not path:
            errors.append(f'Line {idx}: missing object_path / target_path')
        reviewed.append({
            'event_id': event_id, 'timestamp': timestamp, 'timestamp_label': label,
            'timestamp_category': category, 'forensic_interpretation': interpretation,
            'object_path': path, 'source_file': source, 'evidence_reference': ref,
            'review_status': 'NEEDS_CONTEXT', 'is_direct_user_action': 'NO',
            '_key': normalize_path_for_grouping(path) if path else '',
            '_parsed': parsed,
        })

    repeated_ids = {k: count for k, count in seen_ids.items() if count > 1}
    by_type = Counter(r['timestamp_category'] for r in reviewed)
    groups = defaultdict(list)
    for row in reviewed:
        if row['_key']:
            groups[row['_key']].append(row)

    group_summaries = []
    for group in groups.values():
        times = [r['_parsed'] for r in group if r['_parsed'] is not None]
        group_summaries.append({
            'object_path': group[0]['object_path'],
            'event_count': len(group),
            'timestamp_categories': '; '.join(sorted({r['timestamp_category'] for r in group})),
            'timestamp_labels': '; '.join(sorted({r['timestamp_label'] for r in group})),
            'earliest_utc': min(times).isoformat() if times else '',
            'latest_utc': max(times).isoformat() if times else '',
            'event_ids': '; '.join(r['event_id'] for r in group),
            'evidence_references': '; '.join(sorted({r['evidence_reference'] for r in group if r['evidence_reference']})),
            'interpretation': 'Path-based object context; NOT event count of user folder openings',
        })
    group_summaries.sort(key=lambda r: (-r['event_count'], r['object_path'].casefold()))

    OUTPUT.mkdir(parents=True, exist_ok=True)
    audit_file = OUTPUT / 'case01_shellbags_timestamp_audit.csv'
    context_file = OUTPUT / 'case01_shellbags_path_context.csv'
    note_file = ROOT / 'analysis' / 'thi-timeline' / 'case01_shellbags_dfir_review_generated.md'

    audit_cols = ['event_id', 'timestamp', 'timestamp_label', 'timestamp_category',
                  'forensic_interpretation', 'object_path', 'source_file', 'evidence_reference',
                  'review_status', 'is_direct_user_action']
    write_csv(audit_file, reviewed, audit_cols)
    context_cols = ['object_path', 'event_count', 'timestamp_categories', 'timestamp_labels',
                    'earliest_utc', 'latest_utc', 'event_ids', 'evidence_references', 'interpretation']
    write_csv(context_file, group_summaries, context_cols)

    examples = []
    for label, check in [
        ('Network share', lambda p: 'secured_drive\\past projects' in p),
        ('Secret project folders', lambda p: 'secured_drive\\secret project data\\design' in p),
        ('E drive entry', lambda p: 'e:\\rm#1\\secret project data' in p),
    ]:
        match = next((g for g in group_summaries if check(g['object_path'].casefold())), None)
        if match:
            examples.append(f"| {label} | `{match['object_path']}` | {match['event_count']} | Chỉ chứng minh sự hiện diện của dấu vết ShellBags; cần đối chiếu LNK, Jump Lists, source hive/volume và ground truth. |")

    with note_file.open('w', encoding='utf-8') as f:
        f.write('# WinTrace – CASE01 ShellBags Correlation Review (Week 2)\n\n')
        f.write('## 1. Phạm vi, dữ liệu\n\n')
        f.write(f'- Input: `results/case01_shellbags_events.csv` ({len(reviewed)} dòng event).\n')
        f.write(f'- Nhóm đường dẫn theo chuỗi: **{len(group_summaries)}**; không đồng nghĩa số lượng ShellItem duy nhất hoặc lượt mở thư mục.\n')
        f.write(f'- Số event ID lặp: **{len(repeated_ids)}**; cảnh báo dữ liệu: **{len(errors)}**.\n')
        f.write('- Kết quả này là phân tích dữ liệu đầu ra, không phải findings đã được xác minh.\n\n')
        f.write('## 2. Phân loại timestamp\n\n')
        f.write('| Nhóm ngữ nghĩa | Số event | Cách hiểu |\n|---|---:|---|\n')
        interpretations = {
            'TARGET_METADATA': 'Metadata của đối tượng được lưu trong ShellItem; không tự chứng minh hoạt động duyệt thư mục tại mốc đó.',
            'REGISTRY_UPDATE': 'Registry key LastWrite, cần MRUListEx và ngữ cảnh hive.',
            'INFERRED_INTERACTION': 'First/Last Interacted do công cụ suy ra, cần xác nhận điều kiện.',
            'OTHER_OR_UNKNOWN': 'Chưa xác định ngữ nghĩa, cần kiểm tra.'
        }
        for k in ('TARGET_METADATA', 'REGISTRY_UPDATE', 'INFERRED_INTERACTION', 'OTHER_OR_UNKNOWN'):
            f.write(f'| {k} | {by_type[k]} | {interpretations[k]} |\n')
        f.write('\n## 3. Ngữ cảnh đối tượng nổi bật\n\n')
        f.write('| Vùng điều tra | Đường dẫn ShellBags | Số timestamp | Giới hạn |\n|---|---|---:|---|\n')
        for line in examples:
            f.write(line + '\n')
        f.write('\n## 4. Đánh giá prototype correlation (số liệu từ lần chạy trước)\n\n')
        f.write('- 383 events → 6.063 candidate pairs: 4.482 `R02`, 1.581 `R01+R02`.\n')
        f.write('- Bộ lọc rà soát ban đầu còn 452 cặp cùng full-path trong 5 phút; đây không phải 452 user activities.\n')
        f.write('- R02: quan hệ path chỉ nên tạo **object context**, không mặc định là finding hành vi.\n')
        f.write('- R01: chỉ so sánh timestamp có ngữ nghĩa tương thích; gần thời gian không chứng minh quan hệ nhân quả.\n')
        f.write('- R03: ưu tiên bằng chứng bổ trợ thực sự từ LNK/Prefetch/EVTX, không chỉ khác nhãn artifact.\n')
        f.write('- R04/R05: đòi hỏi evidence thực thi/xóa riêng và thứ tự thời gian có nghĩa; ShellBags-only chưa đủ.\n\n')
        f.write('## 5. Proposed correlation policy (đề xuất, CHƯA sửa engine)\n\n')
        f.write('1. Giữ nguyên tất cả timestamp event gốc, kể cả khi cùng path.\n')
        f.write('2. Phân tách `object_context` và `activity_candidate`. Cặp ShellBags/ShellBags không tự là user action finding.\n')
        f.write('3. Phân biệt timestamp `TARGET_METADATA`, `REGISTRY_UPDATE`, `INFERRED_INTERACTION`.\n')
        f.write('4. Chỉ dùng cross-artifact correlation khi case_id khớp, timezone/semantics hợp lệ, có provenance.\n')
        f.write('5. Các kết luận `copied`, `opened file`, `deleted` phải có nguồn chứng cứ phù hợp, đối chiếu Phúc/Quyên.\n\n')
        f.write('## 6. Phụ thuộc & hành động tiếp theo\n\n')
        f.write('- Quyên đang sửa `src/correlation.py` và `tests/test_correlation.py`: không chỉnh hai file này khi chưa thống nhất.\n')
        f.write('- Trao đổi quy tắc ở mục 5 với Quyên; nhận dữ liệu CASE01 LNK/Prefetch/Jump Lists từ Phúc/Nam.\n')
        f.write('- Khi mã nguồn được bàn giao, viết tests cho cross-artifact và false correlations; kiểm tra trên cùng case_id.\n')
        f.write('- Tài liệu cần được review thủ công trước khi commit vì ngữ cảnh nguồn có thể chưa đủ.\n\n')
        f.write('## 7. Tham khảo\n\n')
        f.write('- Microsoft Security, *Leveraging Windows Internals for Forensic Investigation* (ShellBags Guide).\n')
        f.write('- artifacts.help, *Registry – Shellbags*: https://artefacts.help/windows_registry_shellbags.html\n')

    print('\n=== CASE01 SHELLBAGS REVIEW ===')
    print('Input events:', len(reviewed))
    print('Distinct path-text groups:', len(group_summaries))
    for kind in ('TARGET_METADATA', 'REGISTRY_UPDATE', 'INFERRED_INTERACTION', 'OTHER_OR_UNKNOWN'):
        print(f'{kind}: {by_type[kind]}')
    print('Duplicate event IDs:', len(repeated_ids))
    print('Data warnings:', len(errors))
    for msg in errors[:5]:
        print('WARNING:', msg)
    print('\nTOP PATH GROUPS:')
    for row in group_summaries[:5]:
        print(f"{row['event_count']:>3} events | {row['object_path']}")
    print('\nFiles:')
    print(audit_file)
    print(context_file)
    print(note_file)
    print('\nNo source code in src/ or tests/ was modified.')


if __name__ == '__main__':
    main()

