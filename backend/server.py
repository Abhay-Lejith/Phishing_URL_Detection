from flask import Flask, request, jsonify
from flask_cors import CORS  # Add this
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
import joblib
import pandas as pd
import vt
import numpy as np 
import seaborn as sns
import matplotlib.pyplot as plt
import time
import re
import requests
from urllib.parse import urlparse
import re
import whois
import requests
import socket
import nltk
from nltk.corpus import words
from preprocessing import extract_url_features
import nest_asyncio
nest_asyncio.apply()

app = Flask(__name__)
CORS(app)  # Allow frontend requests

class InvertedResidualBlock(nn.Module):
    def __init__(self, in_channels, out_channels):
        super(InvertedResidualBlock, self).__init__()
        self.conv1 = nn.Conv1d(in_channels, in_channels, kernel_size=1, stride=1, padding=0, bias=False)
        self.bn1 = nn.BatchNorm1d(in_channels)
        self.depthwise = nn.Conv1d(in_channels, in_channels, kernel_size=3, stride=1, padding=1, groups=in_channels, bias=False)
        self.bn2 = nn.BatchNorm1d(in_channels)
        self.conv2 = nn.Conv1d(in_channels, out_channels, kernel_size=1, stride=1, padding=0, bias=False)
        self.bn3 = nn.BatchNorm1d(out_channels)
        self.activation = nn.ReLU()
        self.use_residual = in_channels == out_channels
    
    def forward(self, x):
        identity = x
        out = self.conv1(x)
        out = self.bn1(out)
        out = self.activation(out)
        out = self.depthwise(out)
        out = self.bn2(out)
        out = self.activation(out)
        out = self.conv2(out)
        out = self.bn3(out)
        if self.use_residual:
            out += identity
        return self.activation(out)

class TabularCNN(nn.Module):
    def __init__(self, input_dim, num_classes=2, dropout_rate=0.4):
        super(TabularCNN, self).__init__()
        
        self.fc1 = nn.Linear(input_dim, 128) 

        self.conv1 = nn.Conv1d(1, 16, kernel_size=3, stride=1, padding=1)
        self.bn = nn.BatchNorm1d(16, track_running_stats=False)
        self.act1 = nn.ReLU()
        
        self.res_block1 = InvertedResidualBlock(16, 16)
        self.res_block2 = InvertedResidualBlock(16, 16)
        
        self.conv2 = nn.Conv1d(16, 1, kernel_size=3, stride=1, padding=1)
        self.bn2 = nn.BatchNorm1d(1)
        self.act2 = nn.ReLU()

        self.pool = nn.MaxPool1d(kernel_size=2, stride=2)
        
        self.dropout = nn.Dropout(dropout_rate)  
        self.fc2 = nn.Linear(64, 32) 
        self.fc3 = nn.Linear(32, 1)

    def forward(self, x):
        x = self.fc1(x).unsqueeze(1) 

        x = self.conv1(x)
        x = self.bn(x)
        x = self.act1(x)
        
        x = self.res_block1(x)
        x = self.res_block2(x)
        
        x = self.conv2(x)
        x = self.bn2(x)
        x = self.act2(x)
        
        x = self.pool(x)  
        
        x = x.view(x.size(0), -1)  # Flatten 
        
        x = F.relu(self.fc2(x))
        x = self.dropout(x)  
        x = self.fc3(x)
        
        return x  


min_max_values = joblib.load("min_max_values.pkl")

def normalize_single_sample(features):
    """Normalize a single row of extracted features using stored min-max values."""
    for col, (min_val, max_val) in min_max_values.items():
        if col in features and max_val > min_val:  # Avoid division by zero
            features[col] = (features[col] - min_val) / (max_val - min_val)
    return features

def remove_http_https(url):
    """Removes 'http://' or 'https://' from a URL if present."""
    return re.sub(r"^https?://", "", url)


## chatgpt function
def is_valid_url(url):
    """Checks if the given URL is structurally valid."""
    pattern = r"^(?!-)[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?<!-)$"
    return bool(re.match(pattern, url))

## gfg function
def isValidURL(str):
    regex = ("[a-zA-Z0-9@:%._\\+~#?&//=]" +
             "{2,256}\\.[a-z]" +
             "{2,6}\\b([-a-zA-Z0-9@:%" +
             "._\\+~#?&//=]*)")
    p = re.compile(regex)
    if (str == None):
        return False
    if(re.search(p, str)):
        return True
    else:
        return False
    
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url")
    url = remove_http_https(url)
    if not url:
        return jsonify({"nourl": "Please enter a valid URL"})

    if not isValidURL(url) : 
        return jsonify({"notvalid": "Please Enter a Valid URL"})

    features = {}
    features.update(extract_url_features(url))

    normalized_features = normalize_single_sample(features)

    feature_df = pd.DataFrame([normalized_features])

    drop_columns = ['punycode', 'has_port', 'domain_in_brand', 'statistical_report']

    feature_df = feature_df.drop(columns=drop_columns, errors='ignore')  
    features_tensor = torch.tensor(feature_df.values, dtype=torch.float32)

    input_dim = len(feature_df.columns)  
    model = TabularCNN(input_dim= input_dim) 
    model.load_state_dict(torch.load("trained_model_better.pth", map_location=torch.device('cpu')))

    model.eval()

    print("Model loaded successfully!")
    # Step 5: Run Model Inference
    with torch.no_grad():
        output = model(features_tensor)
        prob = torch.sigmoid(output).item()  # Get probability score

    # Step 6: Convert Probability to Label
    is_malicious = bool(prob > 0.5)  # If > 0.5, classify as phishing
    if prob < 0.5:
        prob = 1 - prob

    return jsonify({"is_malicious": is_malicious, "confidence": round(prob, 4)})

# @app.route("/predict_batch", methods=["POST"])
# def predict_batch():
#     if "file" not in request.files:
#         return jsonify({"error": "No file uploaded"}), 400

#     file = request.files["file"]
#     if file.filename == "":
#         return jsonify({"error": "Empty file uploaded"}), 400

#     urls = file.read().decode("utf-8").splitlines()
#     urls = [remove_http_https(url.strip()) for url in urls if url.strip()]

#     predictions = []
    
#     # Load model once
#     model = TabularCNN(input_dim=50)  # Adjust input_dim if needed
#     model.load_state_dict(torch.load("trained_model_better.pth", map_location=torch.device('cpu')))
#     model.eval()

#     for url in urls:
#         if not isValidURL(url):
#             predictions.append({"url": url, "error": "Invalid URL"})
#             continue

#         features = extract_url_features(url)
#         normalized_features = normalize_single_sample(features)

#         feature_df = pd.DataFrame([normalized_features])
#         drop_columns = ['punycode', 'has_port', 'domain_in_brand', 'statistical_report']
#         feature_df = feature_df.drop(columns=drop_columns, errors='ignore')

#         features_tensor = torch.tensor(feature_df.values, dtype=torch.float32)

#         with torch.no_grad():
#             output = model(features_tensor)
#             prob = torch.sigmoid(output).item()
#             is_malicious = bool(prob > 0.5)


#         predictions.append({"url": url, "is_malicious": is_malicious, "confidence": round(prob, 4)})

#     return jsonify({"predictions": predictions})

@app.route("/predict_batch", methods=["POST"])
def predict_batch():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty file uploaded"}), 400

    urls = file.read().decode("utf-8").splitlines()
    urls = [remove_http_https(url.strip()) for url in urls if url.strip()]

    if not urls:
        return jsonify({"error": "No valid URLs found"}), 400

    # Load model once
    model = TabularCNN(input_dim=50)  # Adjust input_dim if needed
    model.load_state_dict(torch.load("trained_model_better.pth", map_location=torch.device('cpu')))
    model.eval()

    valid_urls = []
    invalid_urls = []
    feature_list = []

    for url in urls:
        if not isValidURL(url):
            invalid_urls.append({"url": url, "error": "Invalid URL"})
        else:
            features = extract_url_features(url)
            normalized_features = normalize_single_sample(features)
            feature_df = pd.DataFrame([normalized_features])
            drop_columns = ['punycode', 'has_port', 'domain_in_brand', 'statistical_report']
            feature_df = feature_df.drop(columns=drop_columns, errors='ignore')
            feature_list.append(feature_df.values)
            valid_urls.append(url)

    if not feature_list:
        return jsonify({"error": "No valid URLs to process"}), 400

    # Convert list of feature arrays into a tensor batch
    features_tensor = torch.tensor(np.vstack(feature_list), dtype=torch.float32)

    # Perform batch prediction
    with torch.no_grad():
        outputs = model(features_tensor)
        probs = torch.sigmoid(outputs).squeeze().tolist()

    # Ensure probs is a list (handle single-item batch case)
    if isinstance(probs, float):
        probs = [probs]

    predictions = [
        {"url": url, "is_malicious": bool(prob > 0.5), "confidence": round(1 - prob if prob < 0.5 else prob, 4)}
        for url, prob in zip(valid_urls, probs)
    ]

    return jsonify({"predictions": predictions + invalid_urls})



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
