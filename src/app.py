"""
WinTrace - Streamlit Investigation Dashboard (v2)
Author: Quyen (Validation & Visualization Engineer)
"""

import sys
from pathlib import Path
from datetime import datetime
import json
import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.storage import TimelineStore
from src.schema import VALID_ARTIFACTS
from src.report_generator import ReportGenerator

st.set_page_config(page_title="WinTrace Dashboard", page_icon="🔍", layout="wide")

@st.cache_data
def load_events(db_path: str, start_dt=None, end_dt=None, artifact=None, keyword=None, limit=1000):
    try:
        with TimelineStore(db_path) as store:
            return store.query(start=start_dt, end=end_dt, artifact=artifact, keyword=keyword, limit=limit)
    except Exception as e:
        st.error(f"Error loading database: {e}")
        return []

@st.cache_data
def load_findings(json_path: str):
    try:
        path = Path(json_path)
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) # Trả về list of dicts an toàn
    except Exception as e:
        st.error(f"Error loading findings: {e}")
        return []

def main():
    st.title("🔍 WinTrace - Super Timeline Analyzer")
    st.markdown("Automated Windows Forensic Artifact Extraction & Super Timeline Analysis")

    st.sidebar.header("📁 Data Sources")
    db_path = st.sidebar.text_input("Timeline Database (SQLite)", value="results/case01_timeline.db")
    findings_path = st.sidebar.text_input("Correlation Findings (JSON)", value="results/correlation_findings.json")
    
    st.sidebar.markdown("---")
    st.sidebar.header("🔍 Filters")
    keyword = st.sidebar.text_input("Keyword Search (Path/Message)")
    artifact_filter = st.sidebar.selectbox("Artifact Source", options=["ALL"] + sorted(list(VALID_ARTIFACTS)))
    limit_filter = st.sidebar.number_input("Max Events", min_value=100, max_value=10000, value=1000, step=100)
    
    if st.sidebar.button("Load & Apply Filters"):
        st.session_state['data_loaded'] = True
    
    if 'data_loaded' not in st.session_state:
        st.info("👈 Please click 'Load & Apply Filters' in the sidebar to start.")
        return

    artifact_query = None if artifact_filter == "ALL" else artifact_filter
    keyword_query = None if not keyword else keyword
    
    with st.spinner('Loading data...'):
        events = load_events(db_path, artifact=artifact_query, keyword=keyword_query, limit=limit_filter)
        findings_dict = load_findings(findings_path)

    if not events:
        st.warning("No events found matching your criteria.")
        return

    df_events = pd.DataFrame([e.to_dict() for e in events])
    
    tab1, tab2, tab3 = st.tabs(["📅 Super Timeline", "🔗 Correlation Findings", "📄 Evidence & Reporting"])

    with tab1:
        st.subheader(f"Timeline Events (Showing {len(df_events)} records)")
        display_df = df_events[['event_id', 'timestamp', 'artifact_source', 'message', 'target_path', 'validation_status']]
        st.dataframe(display_df, use_container_width=True, height=400)
        
        st.markdown("### 🔎 Evidence Detail Viewer")
        selected_event_id = st.selectbox("Select an Event ID to view full forensic evidence:", display_df['event_id'].tolist())
        
        if selected_event_id:
            evt = next((e for e in events if e.event_id == selected_event_id), None)
            if evt:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Timestamp:** `{evt.timestamp}` ({evt.timestamp_type})")
                    st.markdown(f"**Artifact:** `{evt.artifact_source}`")
                    st.markdown(f"**Source File:** `{evt.source_file}`")
                with col2:
                    st.markdown(f"**Message:** {evt.message}")
                    st.markdown(f"**Target Path:** `{evt.target_path}`")
                    st.markdown(f"**Validation Status:** `{evt.validation_status}`")
                
                st.info(f"**Evidence Reference:**\n{evt.evidence_reference}")
                with st.expander("Raw Extra Attributes JSON"):
                    st.json(evt.extra_attributes)

    with tab2:
        st.subheader(f"Correlation Findings (Total: {len(findings_dict)})")
        if findings_dict:
            df_findings = pd.DataFrame(findings_dict)
            st.dataframe(df_findings[['finding_id', 'confidence_level', 'matched_rules', 'time_delta_minutes', 'explanation']], use_container_width=True)
            
            selected_finding = st.selectbox("Select Finding ID for details:", df_findings['finding_id'].tolist())
            if selected_finding:
                f_detail = next((f for f in findings_dict if f['finding_id'] == selected_finding), None)
                if f_detail:
                    st.markdown(f"**Rules Matched:** `{', '.join(f_detail.get('matched_rules', []))}`")
                    st.markdown(f"**Event A:** `{f_detail.get('event_a_id')}` - {f_detail.get('event_a_desc')}")
                    st.markdown(f"**Event B:** `{f_detail.get('event_b_id')}` - {f_detail.get('event_b_desc')}")
                    if f_detail.get('evidence_references'):
                        st.markdown("**Corroborating Evidence:**")
                        for ref in f_detail.get('evidence_references', []):
                            st.markdown(f"- `{ref}`")

    with tab3:
        st.subheader("📥 Export Investigation Report")
        html_report = ReportGenerator.generate_html_report(events, findings_dict)
        st.download_button("Download HTML Report", data=html_report, file_name=f"wintrace_report_{datetime.now().strftime('%Y%m%d_%H%M')}.html", mime="text/html")
        
        csv_data = df_events.to_csv(index=False).encode('utf-8')
        st.download_button("Download Filtered Timeline (CSV)", data=csv_data, file_name=f"filtered_timeline_{datetime.now().strftime('%Y%m%d_%H%M')}.csv", mime="text/csv")

if __name__ == "__main__":
    main()