import pandas as pd
import numpy as np
import os
import joblib
import re
import whois
import math
import socket
import ssl
import requests
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    roc_auc_score, 
    precision_recall_fscore_support
)
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import datetime

class AdvancedURLFeatureExtractor:
    @staticmethod
    def get_domain_age(url):
        try:
            domain = urlparse(url).netloc
            domain_info = whois.whois(domain)
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            
            if creation_date:
                domain_age = (datetime.now() - creation_date).days
                return domain_age
        except Exception as e:
            print(f"Domain age extraction error: {e}")
        return 0

    @staticmethod
    def check_ssl_certificate(url):
        try:
            domain = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert()
                    return 1  
        except Exception:
            return 0  

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
        
        
        features['num_subdomains'] = len(parsed_url.netloc.split('.')) - 2
        features['has_suspicious_tld'] = int(parsed_url.netloc.split('.')[-1] in ['tk', 'ml', 'ga', 'cf', 'cn'])
        
        
        features['domain_age'] = AdvancedURLFeatureExtractor.get_domain_age(url)
        features['has_ssl'] = AdvancedURLFeatureExtractor.check_ssl_certificate(url)
        
        
        features['entropy'] = AdvancedURLFeatureExtractor.calculate_entropy(url)
        features['suspicious_words'] = AdvancedURLFeatureExtractor.count_suspicious_words(url)
        
        return features

    @staticmethod
    def calculate_entropy(text):
        """Calculate Shannon entropy of a string"""
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in prob)
        return entropy

    @staticmethod
    def count_suspicious_words(url):
        suspicious_words = ['login', 'verify', 'account', 'secure', 'webscr', 'banking']
        return sum(word in url.lower() for word in suspicious_words)

class ModelTrainer:
    @staticmethod
    def prepare_data(urls, labels):
        features = []
        for url in urls:
            feature_dict = AdvancedURLFeatureExtractor.extract_advanced_features(url)
            features.append(feature_dict)
        
        features_df = pd.DataFrame(features)
        
        
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features_df)
        
        
        joblib.dump(scaler, 'models/feature_scaler.joblib')
        
        return features_scaled, labels

    @staticmethod
    def train_models(X_train, X_test, y_train, y_test):
        models = {
            'random_forest': RandomForestClassifier(n_estimators=300, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=300, random_state=42),
            'neural_network': MLPClassifier(hidden_layer_sizes=(150, 75, 35), random_state=42),
            'xgboost': XGBClassifier(n_estimators=300, random_state=42),
            'lightgbm': LGBMClassifier(n_estimators=300, random_state=42)
        }
        
        results = {}
        for name, model in models.items():
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            
            
            results[name] = {
                'accuracy': model.score(X_test, y_test),
                'precision_recall_f1': precision_recall_fscore_support(y_test, y_pred, average='weighted'),
                'classification_report': classification_report(y_test, y_pred)
            }
            
            
            joblib.dump(model, f'models/{name}_model.joblib')
        
        return results

    @staticmethod
    def create_deep_learning_model(input_shape):
        model = Sequential([
            Dense(256, activation='relu', input_shape=(input_shape,), kernel_regularizer=tf.keras.regularizers.l2(0.001)),
            BatchNormalization(),
            Dropout(0.4),
            Dense(128, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.001)),
            BatchNormalization(),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        optimizer = Adam(learning_rate=0.0001)
        model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=['accuracy'])
        
        return model

def main():
    
    data = pd.read_csv('malicious_phish.csv')
    
    
    X, y = ModelTrainer.prepare_data(data['url'], data['type'])
    print(X)
    
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(X_train)
    
    
    model_results = ModelTrainer.train_models(X_train, X_test, y_train, y_test)
    print(model_results)
    
    
    deep_model = ModelTrainer.create_deep_learning_model(X_train.shape[1])
    
    
    early_stop = EarlyStopping(monitor='val_loss', patience=10)
    print(early_stop)
    reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.2, patience=5)
    print(reduce_lr)
    
    deep_model.fit(
        X_train, y_train, 
        validation_split=0.2, 
        epochs=5, 
        batch_size=32, 
        callbacks=[early_stop, reduce_lr],
        verbose=1
    )
    
    
    deep_model.save('models/advanced_deep_model.h5')
    
    
    for name, results in model_results.items():
        print(f"\n{name.upper()} Model Results:")
        print(f"Accuracy: {results['accuracy']}")
        print("Classification Report:\n", results['classification_report'])

if __name__ == "__main__":
    main()