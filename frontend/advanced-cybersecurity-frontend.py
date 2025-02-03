import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import re
from datetime import datetime

st.set_page_config(
    page_title="Cybersecurity URL Guardian",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)


st.markdown("""
    <style>
    body {
        background-color: #0E1117;
        color: #FFFFFF;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .stButton>button {
        background-color: #2C3E50;
        color: #ECF0F1;
        border: 2px solid #3498DB;
        border-radius: 10px;
        transition: all 0.3s ease;
        width: 100%;
    }
    .stButton>button:hover {
        background-color: #3498DB;
        transform: scale(1.05);
    }
    .prediction-card {
        background-color: #2C3E50;
        border-radius: 10px;
        padding: 15px;
        margin-bottom: 10px;
    }
    .malicious {
        border-left: 5px solid #E74C3C;
    }
    .benign {
        border-left: 5px solid #2ECC71;
    }
    </style>
""", unsafe_allow_html=True)

class CybersecurityDashboard:
    @staticmethod
    def normalize_url(url):
        """
        Prepend "http://" if the URL does not start with http:// or https://.
        """
        if not url.startswith("http://") and not url.startswith("https://"):
            return "http://" + url
        return url

    @staticmethod
    def validate_url(url):
        """Advanced URL validation using regex."""
        url_pattern = re.compile(
            r'^https?://'  
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' 
            r'(?::\d+)?'  
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return bool(url_pattern.match(url))

    @staticmethod
    def make_api_request(url):
        """Send a POST request to the backend for analysis."""
        try:
            response = requests.post(
                'http://localhost:5000/analyze_url',
                json={'url': url},
                timeout=10
            )
            response.raise_for_status() 
            return response.json()
        except requests.exceptions.RequestException as e:
            st.error(f"API Request Failed: {e}")
            return None

    @staticmethod
    def plot_model_predictions(predictions):
        """Create a bar chart of model predictions."""
        model_names = list(predictions.keys())
        confidences = [pred['confidence'] * 100 for pred in predictions.values()]
        colors = ['#E74C3C' if pred['prediction'] == 'Malicious' else '#2ECC71' for pred in predictions.values()]
        
        fig = go.Figure(data=[
            go.Bar(
                x=model_names,
                y=confidences,
                marker_color=colors,
                text=[f"{pred['prediction']}: {pred['confidence']:.2%}" for pred in predictions.values()],
                textposition='auto'
            )
        ])
        fig.update_layout(
            title='Model Prediction Confidence',
            xaxis_title='Models',
            yaxis_title='Confidence (%)',
            template='plotly_dark'
        )
        return fig

    @staticmethod
    def plot_feature_importance(features):
        """Create a bar chart for the extracted URL features."""
        feature_names = list(features.keys())
        feature_values = list(features.values())
        
        fig = px.bar(
            x=feature_names,
            y=feature_values,
            title='URL Feature Analysis',
            labels={'x': 'Features', 'y': 'Value'},
            template='plotly_dark'
        )
        return fig

def main():
    st.title("🔒 Cybersecurity URL Guardian")
    st.markdown("""
    ### Advanced URL Security Analysis Platform  
    Protect your digital assets by analyzing potential security threats in URLs.
    """)

   
    st.sidebar.header("URL Analysis Configuration")
    url = st.sidebar.text_input("Enter URL for Analysis", placeholder="https://example.com")
    
    st.sidebar.subheader("Analysis Settings")
    confidence_threshold = st.sidebar.slider(
        "Confidence Threshold", 
        min_value=0.0, 
        max_value=1.0, 
        value=0.5, 
        step=0.05
    )

    if not url:
        st.warning("Please enter a URL in the sidebar to begin analysis.")
        return

    analysis_result = None

    if st.sidebar.button("Analyze URL", key="analyze_button"):
       
        normalized_url = CybersecurityDashboard.normalize_url(url)
        if not CybersecurityDashboard.validate_url(normalized_url):
            st.error("Invalid URL format. Please enter a valid URL.")
            return

        analysis_result = CybersecurityDashboard.make_api_request(normalized_url)
        if analysis_result is None:
            st.error("No response from API. Please try again later.")
            return
        if "error" in analysis_result:
            st.error(f"Analysis Error: {analysis_result.get('error')}")
            return

        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("Prediction Results")
            predictions = analysis_result.get('predictions', {})
            if not predictions:
                st.error("No predictions returned from the analysis.")
            else:
                for model_name, pred in predictions.items():
                    card_class = 'prediction-card malicious' if pred['prediction'] == 'Malicious' else 'prediction-card benign'
                    st.markdown(f"""
                    <div class="{card_class}">
                        <strong>{model_name.replace('_', ' ').title()}</strong><br>
                        Prediction: {pred['prediction']}<br>
                        Confidence: {pred['confidence']:.2%}
                    </div>
                    """, unsafe_allow_html=True)
        
        with col2:
            st.subheader("URL Details")
            features = analysis_result.get('features', {})
            if features:
                feature_df = pd.DataFrame.from_dict(features, orient='index', columns=['Value'])
                st.dataframe(feature_df)
            else:
                st.info("No feature details available.")

      
        st.subheader("Detailed Visualizations")
        tab1, tab2 = st.tabs(["Model Predictions", "Feature Analysis"])
        
        with tab1:
            if predictions:
                prediction_fig = CybersecurityDashboard.plot_model_predictions(predictions)
                st.plotly_chart(prediction_fig, use_container_width=True)
            else:
                st.write("No model predictions to display.")
        
        with tab2:
            if features:
                feature_fig = CybersecurityDashboard.plot_feature_importance(features)
                st.plotly_chart(feature_fig, use_container_width=True)
            else:
                st.write("No feature data to display.")
        
       
        st.subheader("Security Insights")
        overall_risk = "High" if any(
            pred['prediction'] == 'Malicious' and pred['confidence'] > confidence_threshold
            for pred in predictions.values()
        ) else "Low"
        
        col_risk1, col_risk2 = st.columns(2)
        with col_risk1:
            st.metric("Overall Risk Level", overall_risk)
        with col_risk2:
            st.metric("Analysis Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        
        if st.button("Generate PDF Report"):
            try:
                report_response = requests.post(
                    'http://localhost:5000/generate_report',
                    json=analysis_result,
                    timeout=10
                )
                if report_response.status_code == 200:
                    pdf_bytes = report_response.content
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf"
                    )
                else:
                    st.error("Report generation failed.")
            except Exception as e:
                st.error(f"Report generation error: {e}")

    st.sidebar.markdown("---")
    st.sidebar.info("""
    🛡️ Cybersecurity URL Guardian  
    - Powered by Advanced Machine Learning  
    - Multi-model Threat Detection  
    - Real-time URL Analysis  
    """)

if __name__ == "__main__":
    main()
