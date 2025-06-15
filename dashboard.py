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
    
    # Center the login form
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.title("🛡️ NetSentry Login")
        st.markdown("### Please enter your credentials")
        
        # Add some spacing
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Show login form
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
        options=["Port Scan", "DoS", "Brute Force", "Malware", "Phishing"],
        default=["Port Scan", "DoS", "Brute Force", "Malware", "Phishing"]
    )
    
    severity_levels = st.sidebar.multiselect(
        "Severity Levels",
        options=["Low", "Medium", "High", "Critical"],
        default=["Low", "Medium", "High", "Critical"]
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
    
    # Top metrics with improved styling
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric(
            "Total Alerts",
            len(alerts_df),
            f"Last 24h: {len(alerts_df[alerts_df['timestamp'] >= datetime.now() - timedelta(hours=24)])}"
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        high_critical = len(alerts_df[alerts_df["severity"].isin(["High", "Critical"])])
        st.metric(
            "Active Threats",
            high_critical,
            f"{len(alerts_df[alerts_df['severity'] == 'Critical'])} Critical"
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        unique_sources = len(alerts_df["source_ip"].unique())
        st.metric(
            "Unique Sources",
            unique_sources,
            f"{len(alerts_df[alerts_df['source_ip'].str.startswith('192.168.')])} Internal"
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        unique_types = len(alerts_df["alert_type"].unique())
        st.metric(
            "Alert Types",
            unique_types,
            f"Most common: {alerts_df['alert_type'].mode().iloc[0] if not alerts_df.empty else 'N/A'}"
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Visualizations with improved styling
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Alert Types Distribution")
        if not alerts_df.empty:
            alert_type_counts = alerts_df['alert_type'].value_counts()
            fig = px.pie(
                values=alert_type_counts.values,
                names=alert_type_counts.index,
                title="Distribution of Alert Types",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alerts found for the selected filters")
    
    with col2:
        st.subheader("Top Source IPs")
        if not alerts_df.empty:
            top_sources = alerts_df['source_ip'].value_counts().head(10)
            fig = px.bar(
                x=top_sources.index,
                y=top_sources.values,
                title="Most Active Source IPs",
                labels={'x': 'Source IP', 'y': 'Number of Alerts'},
                color_discrete_sequence=["#1E88E5"]
            )
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alerts found for the selected filters")
    
    # Alerts over time with improved styling
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
            line=dict(color="#1E88E5", width=2),
            marker=dict(size=8)
        ))
        fig.update_layout(
            title="Alert Frequency Over Time",
            xaxis_title="Time",
            yaxis_title="Number of Alerts",
            template="plotly_dark",
            hovermode="x unified"
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alerts found for the selected filters")
    
    # Recent alerts table with improved styling
    st.subheader("Recent Alerts")
    if not alerts_df.empty:
        # Add severity badges and format the table
        def severity_badge(severity):
            color = {
                "Critical": "severity-high",
                "High": "severity-high",
                "Medium": "severity-medium",
                "Low": "severity-low"
            }.get(severity, "")
            return f'<span class="{color}">● {severity}</span>'
        
        # Format the dataframe for display
        display_df = alerts_df.sort_values("timestamp", ascending=False).head(20).copy()
        display_df["severity_badge"] = display_df["severity"].apply(severity_badge)
        display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
        
        # Select and rename columns for display
        columns_to_display = [
            "timestamp", "alert_type", "severity_badge", "source_ip",
            "destination_ip"
        ]
        
        # Add description if it exists
        if "description" in display_df.columns:
            columns_to_display.append("description")
        
        display_df = display_df[columns_to_display]
        
        # Rename columns for display
        column_names = {
            "timestamp": "Time",
            "alert_type": "Alert Type",
            "severity_badge": "Severity",
            "source_ip": "Source IP",
            "destination_ip": "Destination IP",
            "description": "Description"
        }
        display_df.columns = [column_names[col] for col in display_df.columns]
        
        # Display the table
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No alerts found for the selected filters")
    
    # Export buttons with improved styling
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📥 Export to CSV", use_container_width=True):
            try:
                # Prepare data for export
                export_df = alerts_df.copy()
                
                # Format the data
                if not export_df.empty:
                    # Format timestamp
                    export_df['timestamp'] = pd.to_datetime(export_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Generate filename with timestamp
                    filename = f"netsentry_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    
                    # Create download link
                    csv_link = get_download_link(export_df, filename, "Download CSV")
                    
                    if csv_link:
                        st.markdown(csv_link, unsafe_allow_html=True)
                    else:
                        st.error("Failed to generate download link")
                else:
                    st.warning("No data to export")
            except Exception as e:
                st.error(f"Error exporting data: {str(e)}")
    
    with col2:
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.experimental_rerun()
    
    # Footer
    st.markdown("---")
    st.markdown("NetSentry - Network Intrusion Detection System")

def get_download_link(df, filename, text):
    """Generate a download link for the dataframe."""
    try:
        # Create a copy of the dataframe to avoid modifying the original
        export_df = df.copy()
        
        # Format timestamp if it exists
        if 'timestamp' in export_df.columns:
            export_df['timestamp'] = pd.to_datetime(export_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Convert to CSV
        csv = export_df.to_csv(index=False)
        
        # Encode to base64
        b64 = base64.b64encode(csv.encode()).decode()
        
        # Create download link
        href = f'data:file/csv;base64,{b64}'
        
        # Return HTML link
        return f'<a href="{href}" download="{filename}" target="_blank">{text}</a>'
    except Exception as e:
        st.error(f"Error generating download link: {str(e)}")
        return None

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
else:
    show_dashboard()
