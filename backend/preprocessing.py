"""
This is a script for preprocessing the dataset and generating features for each URL.
"""

import vt
import numpy as np 
import pandas as pd 
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
import tldextract
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup
import socket
import nltk
from nltk.corpus import words
import nest_asyncio
import joblib  # To save min-max values
nest_asyncio.apply()


def extract_url_features(url):
    features = {}
    
    features["url_length"] = len(url)
    parsed_url = urllib.parse.urlparse(url)

    def extract_hostname(url):
        # Add scheme if missing
        if "://" not in url:
            url = "http://" + url  # Default to HTTP

        # Use regex to extract the hostname
        match = re.match(r"^(?:https?://)?([^/:]+)", url)
        
        if match:
            return match.group(1)  # Return the extracted hostname
        return None
    hostname = extract_hostname(url)
    features["hostname_length"] = len(hostname)
    
    features["has_ip"] = int(bool(re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', hostname)))

    special_chars = ['.', '-', '@', '?', '&', '|', '=', '_', '~', '%', '/', '*', ':', ',', ';', '$', '%20']
    for i, char in enumerate(special_chars, start=4):
        features[f"char_{char}_count"] = url.count(char)
    
    common_terms = ["www", ".com", "http", "//"]
    for i, term in enumerate(common_terms, start=21):
        features[f"common_term_{term}"] = url.count(term)
    
    features["https"] = int(url.startswith("https"))
    
    features["digit_ratio_url"] = sum(c.isdigit() for c in url) / len(url)
    features["digit_ratio_hostname"] = (sum(c.isdigit() for c in hostname) / len(hostname)) if hostname else 0

    features["punycode"] = int(url.startswith("http://xn--") or url.startswith("http://xn--"))
    
    features["has_port"] = int(":" in parsed_url.netloc)
    
    extracted = tldextract.extract(url)
    tmp = url[url.find(extracted.suffix):len(url)]
    pth = tmp.partition("/")
    path = pth[1] + pth[2]
    features["tld_in_path"] = int(extracted.suffix in parsed_url.path)
    features["tld_in_subdomain"] = int(extracted.suffix in extracted.subdomain)

    features["abnormal_subdomain"] = int(bool(re.search('(http[s]?://(w[w]?|\d))([w]?(\d|-))',url)))
    
    features["subdomain_count"] = extracted.subdomain.count('.') + 1 if extracted.subdomain else 0
    
    features["prefix_suffix"] = int("-" in extracted.domain)
    
    features["is_shortened"] = int(bool(re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)))

    features["ends_with_txt"] = int(bool(url.endswith('.txt')))
    features["tld_in_bad_position"] = int(bool(features["tld_in_path"] == 1 or features["tld_in_subdomain"] == 1))
    features["phish_hints"] = 0

    HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']

    for hint in HINTS:
        features["phish_hints"] += url.lower().count(hint)
    def word_stats(text):
        words = re.split(r'\W+', text)
        words = [word for word in words if word]
        num_words = len(words)
        char_repeat = sum(len(set(word)) != len(word) for word in words)
        shortest = min(map(len, words)) if words else 0
        longest = max(map(len, words)) if words else 0
        avg_length = sum(map(len, words)) / num_words if num_words else 0
        return num_words, char_repeat, shortest, longest, avg_length
        
    features["num_words_url"], features["char_repeat"], features["shortest_word_url"], features["longest_word_url"], features["avg_word_length_url"] = word_stats(url)
    features["num_words_hostname"], _, features["shortest_word_hostname"], features["longest_word_hostname"], features["avg_word_length_hostname"] = word_stats(hostname)
    features["num_words_path"], _, features["shortest_word_path"], features["longest_word_path"], features["avg_word_length_path"] = word_stats(url)

    suspicious_tlds = ['fit','tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 'online', 'click', # Spamhaus
        'country', 'stream', 'download', 'xin', 'racing', 'jetzt',
        'ren', 'mom', 'party', 'review', 'trade', 'accountants', 
        'science', 'work', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
        'accountant', 'realtor', 'top', 'christmas', 'gdn', # Shady Top-Level Domains
        'link', # Blue Coat Systems
        'asia', 'club', 'la', 'ae', 'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr',
        'ce.ke', 'audio', 'gob.pe', 'gov.az', 'website', 'bj', 'mx', 'media', 'sa.gov.au' # statistics
        ]

    features["suspicious_tlds"] = int(bool(extracted.suffix in suspicious_tlds))

    o = urllib.parse.urlsplit(url)
    url_domain = o.hostname, tldextract.extract(url).domain, o.path

    allbrand_txt = open("allbrands.txt", "r")

    def __txt_to_list(txt_object):
        list = []
        for line in txt_object:
            list.append(line.strip())
        txt_object.close()
        return list

    allbrand = __txt_to_list(allbrand_txt)

    features["domain_in_brand"] = int(bool(url_domain in allbrand))
    def statistical_report(url, domain):
        url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
        try:
            ip_address=socket.gethostbyname(domain)
            ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
            if url_match or ip_match:
                return 1
            else:
                return 0
        except:
            return 2

    features["statistical_report"] = statistical_report(url, url_domain)

    return features


# Function to extract external-based features
def extract_external_features(url):
    features = {}
    domain = tldextract.extract(url).registered_domain

    try:
        domain_info = whois.whois(domain)
        # print(domain_info)
        features["whois_registered"] = int(bool(domain_info.domain_name))
        
        def get_first_date(date):
            if isinstance(date, list):
                return date[0]
            return date

        if domain_info.creation_date and domain_info.expiration_date:
            creation_date = get_first_date(domain_info.creation_date)
            expiration_date = get_first_date(domain_info.expiration_date)
            features["domain_registration_length"] = (expiration_date - creation_date).days / 365
        else:
            features["domain_registration_length"] = -1
        
        if domain_info.creation_date:
            features["domain_age"] = (datetime.now() - get_first_date(domain_info.creation_date)).days / 365
        else:
            features["domain_age"] = -1
        
    except:
        features.update({"whois_registered": -1, "domain_registration_length": -1, "domain_age": -1})
    
    try:
        socket.gethostbyname(domain)
        features["dns_record"] = 1
    except socket.gaierror:
        features["dns_record"] = 0

    return features
    
    
def extract_features(url):
    features = {}
    features.update(extract_url_features(url))
    # features.update(extract_external_features(url))
    return features

def normalize_columns(df):
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    for col in numeric_cols:
        if not set(df[col].dropna().unique()).issubset({0, 1}) and df[col].std() > 0:  # Exclude binary columns
            df[col] = (df[col] - df[col].min()) / (df[col].max() - df[col].min())  # Min-max normalization
    return df

def find_and_remove_duplicate_columns(df):
    duplicate_columns = [col for col in df.columns if df[col].nunique() == 1]
    
    if duplicate_columns:
        print("Duplicate Columns:", duplicate_columns)
        df.drop(columns=duplicate_columns, inplace=True)
    return df

def save_min_max_values(df, filename="min_max_values.pkl"):
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    min_max_dict = {col: (df[col].min(), df[col].max()) for col in numeric_cols if df[col].std() > 0}
    joblib.dump(min_max_dict, filename)

def preprocessing(res1):
    # Feature extraction
    features_list = []
    for index, row in res1.iterrows():
        if(index%50000==0):
            print(index)
        url = row[0]
        # print(url)
        label = row[1]
        features = extract_features(url)
        features["Label"] = label 
        features["URL"] = url
        features_list.append(features)
    final_df = pd.DataFrame(features_list)
    final_df = find_and_remove_duplicate_columns(final_df)
    save_min_max_values(final_df)
    final_df = normalize_columns(final_df)
    return final_df
