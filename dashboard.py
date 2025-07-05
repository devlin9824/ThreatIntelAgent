import streamlit as st
import pandas as pd
import plotly.express as px

# Tiêu đề dashboard
st.title("Threat Intelligence IOC Dashboard")

# Đọc dữ liệu từ CSV
try:
    df = pd.read_csv("output/enriched_iocs.csv")
except FileNotFoundError:
    st.error("File 'output/enriched_iocs.csv' not found. Please run enrich_ioc.py first.")
    st.stop()

# Hiển thị bảng IOC
st.subheader("List of Enriched IOCs")
st.dataframe(df)

# Biểu đồ số lượng báo cáo theo quốc gia (AbuseIPDB)
st.subheader("Number of Reports by Country (AbuseIPDB)")
country_counts = df.groupby("ab_country")["ab_reports"].sum().reset_index()
fig = px.bar(country_counts, x="ab_country", y="ab_reports", title="Reports by Country")
st.plotly_chart(fig)

# Biểu đồ danh tiếng VirusTotal
st.subheader("VirusTotal Reputation Distribution")
fig = px.histogram(df, x="vt_reputation", title="Reputation Distribution")
st.plotly_chart(fig)