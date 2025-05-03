import cv2
import pytesseract
import re
import requests
import os
import time
import numpy as np
from flask import Flask, request, jsonify, render_template, send_from_directory
from functools import lru_cache, wraps
from datetime import datetime
from fuzzywuzzy import fuzz
from werkzeug.utils import secure_filename
import dns.resolver
import whois
import socket
import urllib.parse

app = Flask(_name_, static_folder='static', template_folder='templates')

# Configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['NVD_API_KEY'] = os.getenv('NVD_API_KEY', 'bcd34b48-aad2-411b-9310-5b0cb84e634c')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
DOMAIN_EXTENSIONS = r'(?:com|net|org|io|gov|edu|in|uk|de|fr|au|ca|jp|cn|br|ru|info|biz|xyz|co|us|me|tv|cc)'

# Service Database
SERVICE_PATTERNS = [
    r'\b(nginx|apache|httpd|tomcat|iis)\s*[v:]?\s*(\d+\.\d+(?:\.\d+)?)\b',
    r'\b(mysql|postgresql|mongodb|redis|elasticsearch)\s*[v:]?\s*(\d+\.\d+(?:\.\d+)?)\b',
    r'\b(docker|kubernetes|k8s|istio)\s*[v:]?\s*(\d+\.\d+(?:\.\d+)?)\b',
    r'\b([a-z]+)(\d)(\d)(\d+)\b'  # For formats like "nginx1201"
]

SERVICE_CATEGORIES = {
    'web_servers': ['nginx', 'apache', 'httpd', 'tomcat', 'iis'],
    'databases': ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch'],
    'containers': ['docker', 'kubernetes', 'k8s', 'istio']
}

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('templates', exist_ok=True)

def rate_limited(max_per_second):
    min_interval = 1.0 / max_per_second
    def decorate(func):
        last_time_called = 0.0
        @wraps(func)
        def rate_limited_function(*args, **kwargs):
            nonlocal last_time_called
            elapsed = time.time() - last_time_called
            wait_time = min_interval - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
            last_time_called = time.time()
            return func(*args, **kwargs)
        return rate_limited_function
    return decorate

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def enhance_image(image_path):
    """Advanced image preprocessing for OCR"""
    try:
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Could not read image file")

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        gray = cv2.bilateralFilter(gray, 11, 17, 17)
        gray = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                   cv2.THRESH_BINARY, 31, 2)
        gray = cv2.fastNlMeansDenoising(gray, None, 30, 7, 21)
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
        gray = clahe.apply(gray)
        kernel = np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])
        gray = cv2.filter2D(gray, -1, kernel)
        
        height, width = gray.shape
        if max(height, width) < 1500:
            gray = cv2.resize(gray, None, fx=1.5, fy=1.5, interpolation=cv2.INTER_CUBIC)
        
        return gray
    except Exception as e:
        app.logger.error(f"Image processing error: {str(e)}")
        return None

def extract_text(image_path):
    """Improved text extraction with multiple OCR passes"""
    try:
        processed_img = enhance_image(image_path)
        if processed_img is None:
            return ""

        configs = [
            '--oem 3 --psm 6 -c tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-_@/',
            '--oem 3 --psm 11',
            '--oem 3 --psm 4'
        ]

        best_text = ""
        for config in configs:
            text = pytesseract.image_to_string(processed_img, config=config)
            if len(text) > len(best_text):
                best_text = text

        text = re.sub(r'([a-z]+)(\d)(\d)(\d+)', r'\1 \2.\3.\4', best_text)
        return re.sub(r'\s+', ' ', text).strip().lower()
    except Exception as e:
        app.logger.error(f"OCR Error: {str(e)}")
        return ""

def find_services(text):
    """Find services and versions in the text"""
    services = []
    text = text.lower()
    
    for pattern in SERVICE_PATTERNS:
        matches = re.finditer(pattern, text)
        for match in matches:
            name = match.group(1).lower()
            version = match.group(2).lower() if len(match.groups()) > 1 else 'unknown'
            
            valid = False
            for category, keywords in SERVICE_CATEGORIES.items():
                if name in [kw.lower() for kw in keywords]:
                    valid = True
                    break
            
            if valid:
                services.append({
                    'name': name,
                    'version': version,
                    'category': categorize_service(name)
                })

    all_service_names = [name for sublist in SERVICE_CATEGORIES.values() for name in sublist]
    words = re.findall(r'[a-z]{4,}', text)
    
    for word in words:
        if any(s['name'] == word for s in services):
            continue
            
        for pattern in all_service_names:
            if fuzz.ratio(word, pattern.lower()) > 80:
                services.append({
                    'name': pattern.lower(),
                    'version': 'unknown',
                    'category': categorize_service(pattern.lower())
                })
                break

    return services

def categorize_service(service_name):
    service_lower = service_name.lower()
    for category, keywords in SERVICE_CATEGORIES.items():
        if any(kw in service_lower for kw in keywords):
            return category
    return 'other'

def find_domains(text):
    """Find website domains in text"""
    domain_pattern = re.compile(
        r'(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.' + DOMAIN_EXTENSIONS + r')')
    return list(set(domain_pattern.findall(text)))

def passive_recon(domain):
    """Safe passive reconnaissance"""
    results = {'domain': domain, 'dns': {}, 'whois': {}, 'http': {}}
    
    try:
        # DNS Lookup
        for record_type in ['A', 'MX', 'NS']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results['dns'][record_type] = [str(r) for r in answers]
            except Exception:
                pass

        # WHOIS Lookup
        try:
            whois_info = whois.whois(domain)
            results['whois'] = {
                'registrar': whois_info.registrar,
                'creation_date': str(whois_info.creation_date),
                'expiration_date': str(whois_info.expiration_date)
            }
        except Exception:
            pass

        # HTTP Headers
        try:
            with socket.create_connection((domain, 80), timeout=5) as sock:
                sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode())
                response = sock.recv(4096).decode()
                results['http']['headers'] = response.split('\r\n\r\n')[0].split('\r\n')[1:]
        except Exception:
            pass

    except Exception as e:
        app.logger.error(f"Recon error for {domain}: {str(e)}")

    return results

def get_severity_score(cvss_score):
    if not cvss_score:
        return 'unknown'
    score = float(cvss_score)
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'high'
    elif score >= 4.0:
        return 'medium'
    else:
        return 'low'

@lru_cache(maxsize=100)
@rate_limited(1.5)  # 1.5 requests per second (NVD rate limit)
def check_cve(service_name, service_version):
    """Check for CVEs against the NVD database"""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': f"{service_name} {service_version}",
        'resultsPerPage': 20
    }
    
    headers = {
        'apiKey': app.config['NVD_API_KEY']
    }
    
    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = []
        if 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                cve_id = vuln['cve']['id']
                description = next((desc['value'] for desc in vuln['cve']['descriptions'] 
                                 if desc['lang'] == 'en'), 'No description available')
                
                # Get CVSS metrics
                metrics = vuln['cve'].get('metrics', {})
                cvss_data = {}
                base_score = 0.0
                
                if 'cvssMetricV31' in metrics:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    base_score = cvss_data.get('baseScore', 0.0)
                elif 'cvssMetricV30' in metrics:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    base_score = cvss_data.get('baseScore', 0.0)
                elif 'cvssMetricV2' in metrics:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    base_score = cvss_data.get('baseScore', 0.0)
                
                severity = get_severity_score(base_score)
                
                vulnerabilities.append({
                    'id': cve_id,
                    'description': description,
                    'severity': severity,
                    'cvss_score': base_score,
                    'vector': cvss_data.get('vectorString', 'N/A'),
                    'published': vuln['cve'].get('published', ''),
                    'last_modified': vuln['cve'].get('lastModified', '')
                })
        
        return {
            'service': f"{service_name} {service_version}",
            'vulnerabilities': sorted(vulnerabilities, 
                                    key=lambda x: x.get('cvss_score', 0), 
                                    reverse=True),
            'total_vulnerabilities': len(vulnerabilities),
            'highest_severity': max([v['severity'] for v in vulnerabilities], 
                                 key=lambda x: ['unknown', 'low', 'medium', 'high', 'critical'].index(x), 
                                 default='unknown')
        }
        
    except requests.exceptions.RequestException as e:
        app.logger.error(f"NVD API Error: {str(e)}")
        return {
            'service': f"{service_name} {service_version}",
            'error': f"API Error: {str(e)}",
            'total_vulnerabilities': 0,
            'highest_severity': 'unknown'
        }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    try:
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type'}), 400
            
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        text = extract_text(filepath)
        if not text:
            os.remove(filepath)
            return jsonify({'error': 'No text detected in image'}), 400
            
        # Find services and vulnerabilities
        services = find_services(text)
        results = []
        
        for service in services:
            cve_data = check_cve(service['name'], service['version'])
            results.append({
                'service': service['name'],
                'version': service['version'],
                'category': service['category'],
                'vulnerabilities': cve_data['vulnerabilities'],
                'total_vulnerabilities': cve_data['total_vulnerabilities'],
                'highest_severity': cve_data['highest_severity']
            })
        
        # Find domains and perform recon
        domains = find_domains(text)
        domain_results = [passive_recon(domain) for domain in domains]
        
        return jsonify({
            'status': 'success',
            'text': text,
            'results': results,
            'domains': domain_results,
            'timestamp': datetime.now().isoformat(),
            'filename': filename
        })
        
    except Exception as e:
        app.logger.error(f"Scan Error: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'processing_error'
        }), 500

if _name_ == '_main_':
    app.run(host='0.0.0.0', port=5000, debug=True)
