import logging
import os
import urllib.request
import base64
import json
import hmac
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from logging.handlers import RotatingFileHandler

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================
# LOGGING CONFIGURATION
# ============================================
LOG_DIR = os.getenv('LOG_DIR', '/opt/logs')
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
log_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, 'api.log'), 
    maxBytes=10*1024*1024, 
    backupCount=5,
    encoding='utf-8'
)
log_handler.setFormatter(logging.Formatter(LOG_FORMAT))
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.INFO)

# ============================================
# SMN CONFIGURATIONS
# ============================================
SMN_ENDPOINT = os.getenv('SMN_ENDPOINT', 'https://smn.sa-fb-1.eihcs02.com')
AK = os.getenv('HUAWEI_AK', 'YOUR_ACCESS_KEY')
SK = os.getenv('HUAWEI_SK', 'YOUR_SECRET_KEY')
PROJECT_ID = os.getenv('PROJECT_ID', 'YOUR_PROJECT_ID')
TARGET_TOPIC_URN = os.getenv('TARGET_TOPIC_URN', f'urn:smn:sa-fb-1:{PROJECT_ID}:migration_email')

# SSL Configuration
SSL_CERT = os.getenv('SSL_CERT', 'server.crt')
SSL_KEY = os.getenv('SSL_KEY', 'server.key')
FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))

# ============================================
# CONFIGURATION MANAGER
# ============================================
class ConfigManager:
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.load_config()
    
    def load_config(self):
        """Load configuration from JSON file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                app.logger.info(f"Configuration loaded from {self.config_file}")
            else:
                self.config = {
                    "default": {
                        "sistema": "13206 - RTC",
                        "codservico": "13206",
                        "ambiente": "PRO",
                        "severidade": "CRITICAL",
                        "sub_category": "HCS"
                    }
                }
                app.logger.warning(f"Config file {self.config_file} not found. Using defaults.")
        except Exception as e:
            app.logger.error(f"Error loading config: {e}", exc_info=True)
            self.config = {"default": {}}
    
    def get_job_config(self, job_name):
        """Get configuration for specific job or return default"""
        job_configs = self.config.get('job_configs', {})
        
        # Exact match
        if job_name in job_configs:
            app.logger.info(f"Found config for job: {job_name}")
            return job_configs[job_name]
        
        # Wildcard match (e.g., "ETL_*")
        import re
        for pattern, config in job_configs.items():
            if '*' in pattern:
                regex = pattern.replace('*', '.*')
                if re.match(regex, job_name):
                    app.logger.info(f"Matched job {job_name} with pattern {pattern}")
                    return config
        
        # Return default
        app.logger.info(f"Using default config for job: {job_name}")
        return self.config.get('default', {})

config_manager = ConfigManager()

# ============================================
# MAIN ENDPOINT
# ============================================
@app.route('/api/notification', methods=['POST'])
def notification():
    """
    Main endpoint to receive SMN notifications
    Validates signature and processes based on notification type
    """
    app.logger.info("=" * 60)
    app.logger.info("NEW NOTIFICATION RECEIVED")
    app.logger.info("=" * 60)
    
    if not request.is_json:
        app.logger.error("Invalid request: Body is not JSON")
        return jsonify({'code': 400, 'message': 'JSON expected'}), 400

    req_data = request.get_json()
    app.logger.info(f"Request data: {json.dumps(req_data, indent=2, ensure_ascii=False)}")
    
    msg_type = req_data.get('type')
    signature = req_data.get('signature')
    cert_url = req_data.get('signing_cert_url')

    # Signature Verification
    if cert_url and signature:
        app.logger.info("Validating message signature...")
        if not is_message_valid(cert_url, signature, req_data):
            app.logger.error("SIGNATURE VERIFICATION FAILED!")
            return jsonify({'code': 401, 'message': 'Invalid Signature'}), 401
        app.logger.info("Signature verification PASSED")

    # Handle based on notification type
    
    # Subscription Confirmation
    if msg_type == 'SubscriptionConfirmation':
        subscribe_url = req_data.get('subscribe_url')
        app.logger.info(f"Processing subscription confirmation: {subscribe_url}")
        
        try:
            response = requests.get(subscribe_url, verify=False, timeout=10)
            app.logger.info(f"Subscription confirmed. Status: {response.status_code}")
            return jsonify({'code': 200, 'message': 'Subscribed successfully'})
        except Exception as e:
            app.logger.error(f"Subscription confirmation failed: {e}", exc_info=True)
            return jsonify({'code': 500, 'message': 'Subscription failed'}), 500

    # Notification Processing (Main Logic)
    elif msg_type == 'Notification':
        message_body = req_data.get('message')
        app.logger.info(f"Processing notification. Raw message: {message_body}")
        
        try:
            # Extract job information
            job_info = extract_job_info_from_message(message_body)
            app.logger.info(f"Job info extracted: {json.dumps(job_info, indent=2, ensure_ascii=False)}")
            
            # Transform to customer format
            customer_payload = transform_to_customer_format(job_info)
            app.logger.info(f"customer payload: {json.dumps(customer_payload, indent=2, ensure_ascii=False)}")
            
            # Forward to SMN email topic
            success = forward_to_smn(customer_payload)
            
            if success:
                app.logger.info("Message processed and forwarded successfully")
                return jsonify({
                    'code': 200,
                    'message': 'Message processed and forwarded',
                    'data': {
                        'jobname': job_info['jobname'],
                        'jobhour': job_info['jobhour'],
                        'forwarded_to': TARGET_TOPIC_URN
                    }
                })
            else:
                app.logger.error("Failed to forward message to SMN")
                return jsonify({'code': 500, 'message': 'Failed to forward message'}), 500
                
        except Exception as e:
            app.logger.error(f"Error processing notification: {e}", exc_info=True)
            return jsonify({'code': 500, 'message': f'Processing error: {str(e)}'}), 500

    # Unknown type
    app.logger.warning(f"Unknown notification type: {msg_type}")
    return jsonify({'code': 200, 'message': 'Type ignored'})


# ============================================
# JOB INFO EXTRACTION
# ============================================
def extract_job_info_from_message(message_str):
    """
    Extract job information from DataArts message
    """
    try:
        # Parse JSON if string
        if isinstance(message_str, str):
            message_data = json.loads(message_str)
        else:
            message_data = message_str
        
        app.logger.debug(f"Parsed message data: {message_data}")
        
        # Extract job name (try multiple possible field names)
        job_name = (
            message_data.get('jobName') or 
            message_data.get('job_name') or 
            message_data.get('name') or
            message_data.get('taskName') or
            'UnknownJob'
        )
        
        # Extract timestamp
        timestamp = (
            message_data.get('timestamp') or 
            message_data.get('executeTime') or 
            message_data.get('failTime') or
            message_data.get('time')
        )
        
        if timestamp:
            try:
                if isinstance(timestamp, (int, float)):
                    dt = datetime.fromtimestamp(timestamp / 1000)
                elif 'T' in str(timestamp):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                job_hour = dt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                app.logger.warning(f"Error parsing timestamp: {e}")
                job_hour = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        else:
            job_hour = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Extract error message
        error_msg = (
            message_data.get('error') or 
            message_data.get('errorMessage') or 
            message_data.get('failureReason') or
            'Unknown error'
        )
        
        # Get configuration for this job
        job_config = config_manager.get_job_config(job_name)
        
        return {
            'jobname': job_name,
            'jobhour': job_hour,
            'error': error_msg,
            'config': job_config,
            'raw_message': message_data
        }
    
    except Exception as e:
        app.logger.error(f"Error extracting job info: {e}", exc_info=True)
        return {
            'jobname': 'UnknownJob',
            'jobhour': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'error': 'Unknown error',
            'config': config_manager.get_job_config('UnknownJob'),
            'raw_message': {}
        }


# ============================================
# customer FORMAT TRANSFORMATION
# ============================================
def transform_to_customer_format(job_info):
    """
    Transform job info to customer ticket format
    """
    jobname = job_info['jobname']
    jobhour = job_info['jobhour']
    error = job_info['error']
    config = job_info['config']
    
    customer_payload = {
        "description": f"Verificar a falha no {jobname} e reexecutar o que for necessario. JobHour: {jobhour}",
        "severidade": config.get('severidade', 'CRITICAL'),
        "tipo_alerta": "SERVICO",
        "ambiente": config.get('ambiente', 'PRO'),
        "modulo": "DataArts Job",
        "sistema": config.get('sistema', '13206 - RTC'),
        "codservico": config.get('codservico', '13206'),
        "sub_category": config.get('sub_category', 'HCS'),
        "instance": jobname,
        "status": "falha",
        "alarm_name": f"[{config.get('sistema', '13206 - RTC')}] - {config.get('sub_category', 'HCS')} - falha no {jobname}"
    }
    
    return customer_payload


# ============================================
# SMN FORWARDING
# ============================================
def forward_to_smn(payload):
    """
    Forward transformed message to SMN email topic
    Uses HCS SMN REST API with AK/SK signature
    """
    try:
        # Build API URL
        url = f"{SMN_ENDPOINT}/v2/{PROJECT_ID}/notifications/topics/{TARGET_TOPIC_URN}/publish"
        
        # Build request body
        body = {
            "subject": "DataArts Job Failure Alert",
            "message": json.dumps(payload, ensure_ascii=False)
        }
        body_json = json.dumps(body)
        
        app.logger.info(f"Forwarding to SMN: {url}")
        app.logger.debug(f"Request body: {body_json}")
        
        # Sign request with AK/SK
        headers = sign_request(
            method='POST',
            url=url,
            body=body_json,
            ak=AK,
            sk=SK
        )
        
        # Send request
        response = requests.post(
            url,
            headers=headers,
            data=body_json,
            verify=False,  # HCS may use self-signed certs
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        app.logger.info(f"SMN API response: {result}")
        app.logger.info(f"Message ID: {result.get('message_id')}")
        
        return True
    
    except requests.exceptions.RequestException as e:
        app.logger.error(f"HTTP error forwarding to SMN: {e}", exc_info=True)
        if hasattr(e, 'response') and e.response is not None:
            app.logger.error(f"Response status: {e.response.status_code}")
            app.logger.error(f"Response body: {e.response.text}")
        return False
    
    except Exception as e:
        app.logger.error(f"Unexpected error forwarding to SMN: {e}", exc_info=True)
        return False


# ============================================
# AK/SK REQUEST SIGNING
# ============================================
def sign_request(method, url, body, ak, sk):
    """
    Sign HTTP request using Huawei Cloud AK/SK signature algorithm (SDK-HMAC-SHA256)
    """
    parsed = urlparse(url)
    
    # Generate timestamp
    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    
    # Build headers
    headers = {
        'Content-Type': 'application/json',
        'Host': parsed.netloc,
        'X-Sdk-Date': timestamp
    }
    
    # Create canonical request
    canonical_headers = '\n'.join([f"{k.lower()}:{v}" for k, v in sorted(headers.items())])
    signed_headers = ';'.join([k.lower() for k in sorted(headers.keys())])
    
    hashed_payload = hashlib.sha256(body.encode('utf-8')).hexdigest()
    
    canonical_request = f"{method}\n{parsed.path}\n\n{canonical_headers}\n\n{signed_headers}\n{hashed_payload}"
    
    # Create string to sign
    string_to_sign = f"SDK-HMAC-SHA256\n{timestamp}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    
    # Calculate signature
    signature = hmac.new(
        sk.encode('utf-8'), 
        string_to_sign.encode('utf-8'), 
        hashlib.sha256
    ).hexdigest()
    
    # Add authorization header
    headers['Authorization'] = f"SDK-HMAC-SHA256 Access={ak}, SignedHeaders={signed_headers}, Signature={signature}"
    
    app.logger.debug(f"Request headers: {headers}")
    
    return headers


# ============================================
# SIGNATURE VALIDATION
# ============================================
def is_message_valid(signing_cert_url, signature, message):
    """
    Validate message signature using RSA-PSS with SHA256
    Downloads certificate and verifies signature
    """
    try:
        # Download certificate
        app.logger.debug(f"Downloading certificate from: {signing_cert_url}")
        with urllib.request.urlopen(signing_cert_url, timeout=5) as response:
            cert_data = response.read()
        
        # Load certificate and extract public key
        cert = load_pem_x509_certificate(cert_data)
        public_key = cert.public_key()

        # Build canonical message string
        sign_message = build_sign_message(message)
        app.logger.debug(f"Canonical message string:\n{sign_message}")
        
        # Decode signature
        sig_bytes = base64.b64decode(signature)

        # Verify signature
        public_key.verify(
            sig_bytes,
            sign_message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        app.logger.info("Signature verification successful")
        return True
        
    except InvalidSignature:
        app.logger.error("Signature verification failed: Invalid signature")
        return False
    except Exception as e:
        app.logger.error(f"Signature verification error: {e}", exc_info=True)
        return False


def build_sign_message(msg):
    """
    Build canonical string for signature validation
    Format must match SMN specification exactly
    """
    msg_type = msg.get("type")
    
    if msg_type == "Notification":
        parts = [
            "message", msg.get("message", ""),
            "message_id", msg.get("message_id", "")
        ]
        
        # Add subject if present
        if msg.get("subject"):
            parts.extend(["subject", msg.get("subject")])
        
        parts.extend([
            "timestamp", msg.get("timestamp", ""),
            "topic_urn", msg.get("topic_urn", ""),
            "type", "Notification"
        ])
    
    elif msg_type in ["SubscriptionConfirmation", "UnsubscribeConfirmation"]:
        parts = [
            "message", msg.get("message", ""),
            "message_id", msg.get("message_id", ""),
            "subscribe_url", msg.get("subscribe_url", ""),
            "timestamp", msg.get("timestamp", ""),
            "topic_urn", msg.get("topic_urn", ""),
            "type", msg_type
        ]
    
    else:
        parts = []
    
    return "\n".join(parts) + "\n"


# ============================================
# HEALTH CHECK ENDPOINT
# ============================================
@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'config_loaded': config_manager.config is not None
    })


# ============================================
# APPLICATION STARTUP
# ============================================
if __name__ == '__main__':
    app.logger.info("=" * 60)
    app.logger.info("STARTING SMN NOTIFICATION PROXY")
    app.logger.info("=" * 60)
    app.logger.info(f"SMN Endpoint: {SMN_ENDPOINT}")
    app.logger.info(f"Project ID: {PROJECT_ID}")
    app.logger.info(f"Target Topic: {TARGET_TOPIC_URN}")
    app.logger.info(f"SSL Certificate: {SSL_CERT}")
    app.logger.info(f"SSL Key: {SSL_KEY}")
    app.logger.info(f"Port: {FLASK_PORT}")
    app.logger.info("=" * 60)
    
    # Verify SSL files exist
    if not os.path.exists(SSL_CERT):
        app.logger.error(f"SSL certificate not found: {SSL_CERT}")
        exit(1)
    if not os.path.exists(SSL_KEY):
        app.logger.error(f"SSL key not found: {SSL_KEY}")
        exit(1)
    
    # Run Flask with SSL
    app.run(
        host='0.0.0.0',
        port=FLASK_PORT,
        ssl_context=(SSL_CERT, SSL_KEY),  # Enable HTTPS
        debug=False,
        threaded=True
    )
