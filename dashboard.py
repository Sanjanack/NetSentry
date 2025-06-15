import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
from database import Database
from auth import login, logout
import base64
import time

# Page config
st.set_page_config(
    page_title="NetSentry Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        background-color: #0E1117;
        color: #FFFFFF;
    }
    .stButton>button {
        background-color: #1E88E5;
        color: white;
        border-radius: 5px;
        padding: 10px 20px;
    }
    .metric-card {
        background-color: #1E1E1E;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .severity-high { color: #FF4B4B; }
    .severity-medium { color: #FFA726; }
    .severity-low { color: #66BB6A; }
    .welcome-container {
        text-align: center;
        padding: 50px 20px;
    }
    .feature-card {
        background-color: #1E1E1E;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        text-align: center;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize database
db = Database()

def show_welcome_page():
    """Display the welcome page before login."""
    st.markdown('<div class="welcome-container">', unsafe_allow_html=True)
    st.title("🛡️ Welcome to NetSentry")
    st.markdown("""
        ### Your Network Security Guardian
        
        NetSentry is a lightweight, user-friendly Network Intrusion Detection System designed for small organizations
        and individuals who need basic network security monitoring without the complexity of enterprise solutions.
    """)
    
    # Feature cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)
        st.markdown("### 🔍 Monitor")
        st.markdown("Real-time network traffic analysis")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)
        st.markdown("### 🚨 Detect")
        st.markdown("Advanced threat detection")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)
        st.markdown("### 📊 Analyze")
        st.markdown("Interactive visualizations")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown('<div class="feature-card">', unsafe_allow_html=True)
        st.markdown("### 🤖 AI-Powered")
        st.markdown("Machine learning detection")
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("""
        #### How It Works
        1. **Monitor**: Continuously scans network traffic for suspicious patterns
        2. **Detect**: Identifies common threats like port scanning, DoS attacks, and brute force attempts
        3. **Alert**: Provides real-time notifications and detailed analysis
        4. **Protect**: Helps you respond quickly to potential security threats
    """)
    
    if st.button("🚀 Start Monitoring", use_container_width=True):
        st.session_state.show_login = True
        st.experimental_rerun()
    
    st.markdown('</div>', unsafe_allow_html=True)

def show_login_page():
    """Display the login page."""
    st.markdown('<div class="welcome-container">', unsafe_allow_html=True)
    st.title("🛡️ NetSentry Login")
    st.markdown("### Please login to access the dashboard")
    
    # Display login credentials
    st.info("Default credentials:\n- Username: admin\n- Password: admin123")
    
    # Add some spacing
    st.markdown("<br>", unsafe_allow_html=True)
    
    if login():
        st.session_state.authenticated = True
        st.experimental_rerun()
    
    st.markdown('</div>', unsafe_allow_html=True)

def show_dashboard():
    """Display the main dashboard after login."""
    # Sidebar
    st.sidebar.title("NetSentry Dashboard")
    st.sidebar.markdown("---")
    
    # Logout button
    if st.sidebar.button("🚪 Logout"):
        logout()
        return
    
    # Monitoring control
    monitoring_status = st.sidebar.radio(
        "Monitoring Status",
        ["Active", "Paused"],
        index=0,
        key="monitoring_status"
    )
    
    # Filter options
    st.sidebar.markdown("### Filters")
    date_range = st.sidebar.date_input(
        "Date Range",
        value=(datetime.now() - timedelta(days=1), datetime.now())
    )
    
    alert_types = st.sidebar.multiselect(
        "Alert Types",
        options=["Port Scan", "DoS", "Brute Force", "Anomaly", "Other"],
        default=["Port Scan", "DoS", "Brute Force", "Anomaly"]
    )
    
    severity_levels = st.sidebar.multiselect(
        "Severity Levels",
        options=["High", "Medium", "Low"],
        default=["High", "Medium", "Low"]
    )
    
    # Main content
    st.title("🛡️ NetSentry Dashboard")
    st.subheader("Live Network Security Monitoring")
    
    # Get data
    alerts_df = db.get_recent_alerts()
    stats = db.get_alert_stats()
    
    # Apply filters
    if not alerts_df.empty:
        alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"])
        mask = (
            (alerts_df["timestamp"].dt.date >= date_range[0]) &
            (alerts_df["timestamp"].dt.date <= date_range[1]) &
            (alerts_df["alert_type"].isin(alert_types)) &
            (alerts_df["severity"].isin(severity_levels))
        )
        alerts_df = alerts_df[mask]
    
    # Top metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Total Alerts", stats["total_alerts"])
        st.markdown('</div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Active Threats", len(alerts_df[alerts_df["severity"] == "High"]))
        st.markdown('</div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Unique Sources", len(alerts_df["source_ip"].unique()))
        st.markdown('</div>', unsafe_allow_html=True)
    with col4:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Alert Types", len(alerts_df["alert_type"].unique()))
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Alert Types Distribution")
        fig = px.pie(
            stats["alert_types"],
            values="count",
            names="alert_type",
            title="Distribution of Alert Types",
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Top Source IPs")
        fig = px.bar(
            stats["top_sources"],
            x="source_ip",
            y="count",
            title="Most Active Source IPs",
            color_discrete_sequence=["#1E88E5"]
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Alerts over time
    st.subheader("Alerts Over Time")
    if not alerts_df.empty:
        time_series = alerts_df.groupby(alerts_df["timestamp"].dt.floor("H")).size().reset_index()
        time_series.columns = ["timestamp", "count"]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=time_series["timestamp"],
            y=time_series["count"],
            mode="lines+markers",
            name="Alerts",
            line=dict(color="#1E88E5")
        ))
        fig.update_layout(
            title="Alert Frequency Over Time",
            xaxis_title="Time",
            yaxis_title="Number of Alerts",
            template="plotly_dark"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Recent alerts table
    st.subheader("Recent Alerts")
    if not alerts_df.empty:
        # Add severity badges
        def severity_badge(severity):
            color = {
                "High": "severity-high",
                "Medium": "severity-medium",
                "Low": "severity-low"
            }.get(severity, "")
            return f'<span class="{color}">● {severity}</span>'
        
        alerts_df["severity_badge"] = alerts_df["severity"].apply(severity_badge)
        
        # Display table
        st.dataframe(
            alerts_df.sort_values("timestamp", ascending=False).head(20),
            use_container_width=True,
            hide_index=True
        )
    
    # Export buttons
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📥 Export to CSV"):
            csv_link = get_download_link(
                alerts_df,
                f"netsentry_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "Download CSV"
            )
            st.markdown(csv_link, unsafe_allow_html=True)
    
    with col2:
        if st.button("🔄 Refresh Data"):
            st.experimental_rerun()
    
    # Footer
    st.markdown("---")
    st.markdown("NetSentry - Network Intrusion Detection System")

def get_download_link(df, filename, text):
    """Generate a download link for the dataframe."""
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    href = f'data:file/csv;base64,{b64}'
    return f'<a href="{href}" download="{filename}">{text}</a>'

# Initialize session state
if 'show_login' not in st.session_state:
    st.session_state.show_login = False
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

# Main app flow
if not st.session_state.show_login:
    show_welcome_page()
elif not st.session_state.authenticated:
    show_login_page()
    if st.session_state.authenticated:
        st.experimental_rerun()
else:
    show_dashboard()
