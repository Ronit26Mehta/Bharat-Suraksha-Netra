import os
import uuid
import logging
from datetime import datetime
import re
import whois
import socket
import ssl
from urllib.parse import urlparse

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import joblib
import tensorflow as tf
import numpy as np
import pandas as pd
import requests
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet


logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s: %(message)s',
    filename='url_security_analysis_log.txt'
)


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})




models_dict = {}
scaler = None

try:
    scaler = joblib.load('models/feature_scaler.joblib')
    logging.info("Scaler loaded successfully.")
except Exception as e:
    logging.error(f"Error loading scaler: {e}")


model_files = {
    'random_forest': 'models/best_random_forest_model.joblib',
    'gradient_boosting': 'models/best_gradient_boosting_model.joblib',
    'neural_network': 'models/best_neural_network_model.joblib',
    'xgboost': 'models/best_xgboost_model.joblib',
    'lightgbm': 'models/best_lightgbm_model.joblib'
}

for model_name, path in model_files.items():
    try:
        models_dict[model_name] = joblib.load(path)
        logging.info(f"{model_name} loaded from {path}.")
    except Exception as e:
        logging.error(f"Error loading {model_name} model from {path}: {e}")


try:
    models_dict['deep_learning'] = tf.keras.models.load_model('models/best_deep_learning_model.h5')
    logging.info("Deep learning model loaded successfully.")
except Exception as e:
    logging.error(f"Error loading deep learning model: {e}")




class AdvancedURLFeatureExtractor:
    @staticmethod
    def get_domain_age(url):
        try:
            domain = urlparse(url).netloc
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                return (datetime.now() - creation_date).days
        except Exception as e:
            logging.error(f"Domain age extraction error for {url}: {e}")
        return 0

    @staticmethod
    def check_ssl_certificate(url):
        domain = urlparse(url).netloc
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    _ = secure_sock.getpeercert()
                    return 1
        except Exception as e:
            logging.info(f"SSL certificate check failed for {url}: {e}")
            return 0

    @staticmethod
    def calculate_entropy(text):
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in prob)

    @staticmethod
    def count_suspicious_words(url):
        suspicious_words = ['login', 'verify', 'account', 'secure', 'webscr', 'banking']
        return sum(word in url.lower() for word in suspicious_words)

    @staticmethod
    def extract_advanced_features(url):
        features = {}
        parsed_url = urlparse(url)
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed_url.netloc)
        features['path_length'] = len(parsed_url.path)
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_special_chars'] = sum(not c.isalnum() and not c.isspace() for c in url)
        features['has_ip'] = int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)))
        features['num_subdomains'] = max(0, len(parsed_url.netloc.split('.')) - 2)
        features['has_suspicious_tld'] = int(parsed_url.netloc.split('.')[-1] in ['tk', 'ml', 'ga', 'cf', 'cn'])
        features['domain_age'] = AdvancedURLFeatureExtractor.get_domain_age(url)
        features['has_ssl'] = AdvancedURLFeatureExtractor.check_ssl_certificate(url)
        features['entropy'] = AdvancedURLFeatureExtractor.calculate_entropy(url)
        features['suspicious_words'] = AdvancedURLFeatureExtractor.count_suspicious_words(url)
        return features




class SecurityReportGenerator:
    @staticmethod
    def extract_domain_details(url):
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            domain_info = whois.whois(domain)
            ssl_details = SecurityReportGenerator.check_ssl_certificate(domain)
            geo_details = SecurityReportGenerator.get_ip_geolocation(domain)
            return {
                'domain_name': domain,
                'registrar': domain_info.get('registrar', 'Unknown'),
                'creation_date': str(domain_info.get('creation_date', 'N/A')),
                'expiration_date': str(domain_info.get('expiration_date', 'N/A')),
                'ssl_details': ssl_details,
                'geolocation': geo_details
            }
        except Exception as e:
            logging.error(f"Domain details extraction error: {e}")
            return {}

    @staticmethod
    def check_ssl_certificate(domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert()
                    return {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'expiration': cert.get('notAfter', 'N/A'),
                        'subject': dict(x[0] for x in cert.get('subject', []))
                    }
        except Exception as e:
            return {'valid': False, 'error': str(e)}

    @staticmethod
    def get_ip_geolocation(domain):
        try:
            ip_address = socket.gethostbyname(domain)
            response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
            return {
                'ip_address': ip_address,
                'country': response.get('country_name', 'Unknown'),
                'city': response.get('city', 'Unknown'),
                'region': response.get('region', 'Unknown'),
                'org': response.get('org', 'Unknown')
            }
        except Exception as e:
            logging.error(f"Geolocation lookup error: {e}")
            return {}

    @staticmethod
    def generate_comprehensive_pdf_report(analysis_data):
        
        os.makedirs("reports", exist_ok=True)
        
        file_name = f"security_report_{uuid.uuid4()}.pdf"
        report_filename = os.path.join("reports", file_name)
        
        doc = SimpleDocTemplate(report_filename, pagesize=letter)
        styles = getSampleStyleSheet()
        report_content = []

        
        title = Paragraph("URL Security Analysis Report", styles['Title'])
        report_content.append(title)
        report_content.append(Spacer(1, 12))

        
        url_details = [
            ['URL', analysis_data.get('url', 'N/A')],
            ['Analysis Timestamp', str(datetime.now())],
            ['Request ID', analysis_data.get('request_id', 'N/A')]
        ]
        url_details_table = Table(url_details, colWidths=[100, 300])
        url_details_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 12),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        report_content.append(url_details_table)
        report_content.append(Spacer(1, 12))

        
        predictions = analysis_data.get('predictions', {})
        pred_details = [['Model', 'Prediction', 'Confidence']]
        for model, pred in predictions.items():
            pred_details.append([
                model, 
                pred.get('prediction', 'N/A'), 
                f"{pred.get('confidence', 0):.2%}"
            ])
        pred_table = Table(pred_details)
        pred_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 12),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        report_content.append(Paragraph("Model Prediction Results", styles['Heading2']))
        report_content.append(pred_table)
        report_content.append(Spacer(1, 12))

        
        domain_details = analysis_data.get('domain_details', {})
        domain_info = [
            ['Domain Registrar', domain_details.get('registrar', 'N/A')],
            ['Creation Date', domain_details.get('creation_date', 'N/A')],
            ['Expiration Date', domain_details.get('expiration_date', 'N/A')]
        ]
        domain_table = Table(domain_info)
        domain_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 12),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        report_content.append(Paragraph("Domain Registration Details", styles['Heading2']))
        report_content.append(domain_table)

        doc.build(report_content)
        logging.info(f"PDF report generated and saved as: {report_filename}")
        return report_filename




class URLSecurityAnalyzer:
    @staticmethod
    def comprehensive_url_analysis(url):
        
        features = AdvancedURLFeatureExtractor.extract_advanced_features(url)
        features_df = pd.DataFrame([features])
        
        
        if scaler is None:
            logging.error("Scaler is not available.")
            return {"error": "Feature scaler not available."}
        try:
            features_scaled = scaler.transform(features_df)
        except Exception as e:
            logging.error(f"Error scaling features: {e}")
            return {"error": f"Error scaling features: {e}"}
        
        
        predictions = {}
        for model_name, model in models_dict.items():
            try:
                if model_name == 'deep_learning':
                    
                    proba = model.predict(features_scaled)[0][0]
                else:
                    if hasattr(model, "predict_proba"):
                        proba = model.predict_proba(features_scaled)[0][1]
                    else:
                        pred = model.predict(features_scaled)[0]
                        proba = 1.0 if pred == 1 else 0.0

                prediction = "Malicious" if proba >= 0.5 else "Benign"
                predictions[model_name] = {"prediction": prediction, "confidence": float(proba)}
            except Exception as e:
                logging.error(f"Error predicting with {model_name}: {e}")
                predictions[model_name] = {"prediction": "Error", "confidence": 0}
        
        
        domain_details = SecurityReportGenerator.extract_domain_details(url)
        
        
        analysis_result = {
            "url": url,
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "predictions": predictions,
            "domain_details": domain_details,
            "features": features
        }
        return analysis_result




@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json(force=True)
        url = data.get("url")
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        logging.info(f"Analysis Request - URL: {url}")
        analysis_result = URLSecurityAnalyzer.comprehensive_url_analysis(url)
        return jsonify(analysis_result)
    except Exception as e:
        logging.error(f"Analysis Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/generate_report', methods=['POST'])
def generate_report():
    try:
        analysis_data = request.get_json(force=True)
        
        report_path = SecurityReportGenerator.generate_comprehensive_pdf_report(analysis_data)
        
        return send_file(
            report_path,
            mimetype="reports",
            as_attachment=True,
            download_name=os.path.basename(report_path)
        )
    except Exception as e:
        logging.error(f"application/pdf")
        return jsonify({"Report Generation Error: {str(e)}": str(e)}), 500




if __name__ == "error":
    os.makedirs("__main__", exist_ok=True)
    app.run(debug=False, host="reports", port=5000,use_reloader=False)
