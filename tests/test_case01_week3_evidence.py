"""Evidence-grounding tests for Thi's CASE01 C1, C2 and C5 candidates.

Copy to tests/ in the repository root and run pytest.
These check source artifact consistency, NOT the correlation engine and NOT
independent forensic verification. They require committed Phuc output CSVs.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHUC = ROOT / 'analysis' / 'phuc-artifacts'


def _csv(relpath):
    path = ROOT / relpath
    assert path.is_file(), f'Missing committed evidence file: {path}'
    with path.open(encoding='utf-8-sig', newline='') as fh:
        return list(csv.DictReader(fh))


def _row_at_line(relpath, line_number):
    """For the committed one-record-per-line CSVs, header is L1, row 1 is L2."""
    data = _csv(relpath)
    assert 2 <= line_number <= len(data) + 1
    return data[line_number - 2]


def _sb(event_id):
    matches = [x for x in _csv('results/case01_shellbags_events.csv')
               if x['event_id'] == event_id]
    assert len(matches) == 1, f'Expected one ShellBag {event_id}'
    row = matches[0]
    return row, json.loads(row['extra_attributes'])


def _utc(s):
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    if len(s) == 19:  # Phuc's CSVs encode UTC without a trailing offset
        s += '+00:00'
    dt = datetime.fromisoformat(s)
    assert dt.tzinfo is not None
    return dt.astimezone(timezone.utc)


def test_c1_directory_navigation_before_excel_jumplist():
    sb, meta = _sb('CASE01-SB0133')
    jl = _row_at_line('analysis/phuc-artifacts/tool_output/jlecmd/AutomaticDestinations_fromF.csv', 23)
    lnk = _row_at_line('analysis/phuc-artifacts/tool_output/lecmd/LECmd_Output_fromF.csv', 2)
    assert sb['timestamp'] == '2015-03-23T20:24:15+00:00'
    assert meta['timestamp_type'] == 'ShellBag_FirstInteracted'
    assert meta['semantic_class'] == 'user_interaction'
    assert meta['source_line'] == 'Deduplicated.csv:L106'
    assert meta['fs_path'].lower().endswith('\\secret project data\\pricing decision')
    assert jl['AppIdDescription'] == 'Microsoft Excel 12'
    assert jl['Path'].lower().endswith('\\(secret_project)_pricing_decision.xlsx')
    assert _utc(jl['LastModified']) == _utc(lnk['SourceCreated'])
    assert int((_utc(jl['LastModified']) - _utc(sb['timestamp'])).total_seconds()) == 158
    sb_later, _ = _sb('CASE01-SB0158')
    assert _utc(sb_later['timestamp']) > _utc(jl['LastModified'])


def test_c2_temporally_valid_network_share_alias_and_single_shellbag_source():
    sb, meta = _sb('CASE01-SB0147')
    twin_type, meta2 = _sb('CASE01-SB0148')
    jl = _row_at_line('analysis/phuc-artifacts/tool_output/jlecmd/AutomaticDestinations_fromF.csv', 21)
    lnk = _row_at_line('analysis/phuc-artifacts/tool_output/lecmd/LECmd_Output_fromF.csv', 15)
    volumes = _csv('analysis/phuc-artifacts/volume_map_case01.csv')
    alias = next(row for row in volumes if row['volume_alias'] == 'V:')
    at_time = _utc(jl['LastModified'])
    assert _utc(alias['valid_from_utc']) <= at_time <= _utc(alias['valid_to_utc'])
    assert alias['canonical_volume'].lower().startswith('\\\\10.11.11.128\\secured_drive')
    assert sb['target_path'].lower().startswith('v:\\')
    assert jl['Path'].lower().startswith('v:\\')
    assert '[secret_project]_final_meeting.pptx' in jl['Path'].lower()
    assert lnk['NetworkPath'].lower().startswith('\\\\10.11.11.128\\secured_drive')
    assert '[secret_project]_final_meeting.pptx' in lnk['CommonPath'].lower()
    assert sb['timestamp'] == twin_type['timestamp']
    assert meta['source_line'] == meta2['source_line'] == 'Deduplicated.csv:L62'
    assert int((at_time - _utc(sb['timestamp'])).total_seconds()) == 4


def test_c5_word_prefetch_and_recent_document_source_timestamps():
    pf_rows = _csv('analysis/phuc-artifacts/tool_output/pecmd/PECmd_Output_Timeline_fromF.csv')
    pf = [row for row in pf_rows
          if row['ExecutableName'].upper().endswith('\\WINWORD.EXE')
          and row['RunTime'] == '2015-03-25 15:24:48']
    assert len(pf) == 1
    lnk = _row_at_line('analysis/phuc-artifacts/tool_output/lecmd/LECmd_Output_fromF.csv', 9)
    jl = _row_at_line('analysis/phuc-artifacts/tool_output/jlecmd/AutomaticDestinations_fromF.csv', 19)
    assert 'resignation_letter_' in lnk['LocalPath'].lower()
    assert lnk['LocalPath'].lower().endswith('.docx')
    assert jl['Path'].lower().endswith('resignation_letter_(iaman_informant).docx')
    assert _utc(lnk['SourceModified']) == _utc(jl['LastModified'])
    assert int((_utc(lnk['SourceModified']) - _utc(pf[0]['RunTime'])).total_seconds()) == 260
    # NOTE: inspect PECmd_Output_fromF.csv FilesLoaded manually with Phuc.
    # That check is deliberately NOT marked verified by this test.


def test_reused_drive_letter_is_not_a_unique_device_identifier():
    volumes = _csv('analysis/phuc-artifacts/volume_map_case01.csv')
    e_volumes = [r for r in volumes if r['volume_alias'] == 'E:']
    assert len(e_volumes) >= 2
    assert len({r['canonical_volume'] for r in e_volumes}) >= 2
    # An E: path alone cannot establish volume identity across timestamps.
