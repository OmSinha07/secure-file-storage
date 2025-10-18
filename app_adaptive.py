# ============================================
# FILE: app_adaptive.py (FIXED - Handles old data)
# ============================================

import os
from flask import Flask, request, render_template, send_file, flash, redirect, url_for, session
from werkzeug.utils import secure_filename
import tempfile
import time

# Import adaptive modules
from ml_classifier import ml_classifier
from crypto_utils_adaptive import adaptive_crypto
from key_storage import key_storage
from file_storage import file_storage

app = Flask(__name__)
app.secret_key = 'your-secret-key-ml-adaptive-crypto-change-in-production'

UPLOAD_FOLDER = 'encrypted_uploads'
MAX_FILE_SIZE = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_current_user():
    return session.get('user_id', 'default_user')

@app.route('/')
def index():
    """Main page with ML-adaptive encryption info"""
    user_id = get_current_user()
    
    # Generate keys for all sensitivity levels if not exists
    if not key_storage.has_user_keys(user_id):
        for sensitivity in ['LOW', 'MEDIUM', 'HIGH']:
            public_key, private_key, config_name = adaptive_crypto.generate_key_pair(sensitivity)
            key_storage.store_user_keys(public_key, private_key, user_id, sensitivity)
        flash(f'🔑 Generated adaptive encryption keys (LOW/MEDIUM/HIGH)!')
    
    # Get user's files with sensitivity info
    user_files = file_storage.get_user_files(user_id)
    
    # FIX: Add default values for old files missing ML fields
    for file_id, file_info in user_files.items():
        if 'ml_confidence' not in file_info:
            file_info['ml_confidence'] = 0.0
        if 'sensitivity' not in file_info:
            file_info['sensitivity'] = 'MEDIUM'
        if 'entropy' not in file_info:
            file_info['entropy'] = 0.0
        if 'crypto_config' not in file_info:
            file_info['crypto_config'] = 'AES-256 + RSA-2048'
    
    return render_template('index_ml_adaptive.html', files=user_files, user_id=user_id)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle ML-adaptive encrypted file upload"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '' or not (file and allowed_file(file.filename)):
        flash('Invalid file')
        return redirect(url_for('index'))
    
    try:
        start_time = time.time()
        user_id = get_current_user()
        
        # Read file data
        file_data = file.read()
        original_filename = secure_filename(file.filename)
        
        # ML Classification
        ml_result = ml_classifier.predict_sensitivity(file_data, original_filename)
        sensitivity = ml_result['sensitivity']
        confidence = ml_result['confidence']
        features = ml_result['features']
        
        # Get appropriate keys
        user_keys = key_storage.get_user_keys(user_id, sensitivity)
        public_key = user_keys['public_key']
        
        # Adaptive encryption
        encrypted_file_data, encrypted_aes_key, crypto_config = adaptive_crypto.encrypt_file(
            file_data, public_key, sensitivity
        )
        
        # Save encrypted file
        encrypted_filename = f"enc_{sensitivity.lower()}_{user_id}_{len(file_storage.files)}.dat"
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        with open(encrypted_filepath, 'w') as f:
            f.write(encrypted_file_data)
        
        # Store metadata with ML info
        file_id = file_storage.store_file_info(
            encrypted_filename,
            original_filename,
            encrypted_aes_key,
            len(file_data),
            user_id,
            sensitivity=sensitivity,
            ml_confidence=confidence,
            entropy=features['entropy'],
            crypto_config=crypto_config
        )
        
        encryption_time = (time.time() - start_time) * 1000  # ms
        
        flash(f'🧠 ML Analysis: {sensitivity} sensitivity ({confidence*100:.1f}% confidence)')
        flash(f'🔒 Encrypted with {crypto_config} in {encryption_time:.1f}ms')
        
        return render_template('success_ml_adaptive.html',
                             filename=original_filename,
                             file_id=file_id,
                             sensitivity=sensitivity,
                             confidence=confidence,
                             features=features,
                             crypto_config=crypto_config,
                             encryption_time=encryption_time)
    
    except Exception as e:
        flash(f'❌ Error: {str(e)}')
        return redirect(url_for('index'))

@app.route('/download/<file_id>')
def download_file(file_id):
    """Handle adaptive encrypted file download"""
    try:
        user_id = get_current_user()
        
        # Get file metadata
        file_info = file_storage.get_file_info(file_id)
        if not file_info or file_info['user_id'] != user_id:
            flash('File not found or access denied')
            return redirect(url_for('index'))
        
        sensitivity = file_info.get('sensitivity', 'MEDIUM')
        
        # Get appropriate private key
        user_keys = key_storage.get_user_keys(user_id, sensitivity)
        private_key = user_keys['private_key']
        
        # Read encrypted file
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_info['filename'])
        with open(encrypted_filepath, 'r') as f:
            encrypted_file_data = f.read()
        
        # Adaptive decryption
        decrypted_data = adaptive_crypto.decrypt_file(
            encrypted_file_data,
            file_info['encrypted_aes_key'],
            private_key,
            sensitivity
        )
        
        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(decrypted_data)
        temp_file.close()
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=file_info['original_filename']
        )
    
    except Exception as e:
        flash(f'❌ Decryption failed: {str(e)}')
        return redirect(url_for('index'))

@app.route('/ml-stats')
def ml_stats():
    """Show ML model statistics"""
    user_id = get_current_user()
    user_files = file_storage.get_user_files(user_id)
    
    # FIX: Handle missing ML fields in statistics
    for file_id, file_info in user_files.items():
        if 'ml_confidence' not in file_info:
            file_info['ml_confidence'] = 0.0
        if 'sensitivity' not in file_info:
            file_info['sensitivity'] = 'MEDIUM'
        if 'entropy' not in file_info:
            file_info['entropy'] = 0.0
        if 'crypto_config' not in file_info:
            file_info['crypto_config'] = 'AES-256 + RSA-2048'
    
    # Calculate statistics
    stats = {
        'total': len(user_files),
        'low': sum(1 for f in user_files.values() if f.get('sensitivity') == 'LOW'),
        'medium': sum(1 for f in user_files.values() if f.get('sensitivity') == 'MEDIUM'),
        'high': sum(1 for f in user_files.values() if f.get('sensitivity') == 'HIGH'),
        'avg_confidence': sum(f.get('ml_confidence', 0) for f in user_files.values()) / len(user_files) if user_files else 0
    }
    
    return render_template('ml_stats.html', stats=stats, files=user_files)

@app.route('/keys')
def show_keys():
    """Show user's encryption keys for all sensitivity levels"""
    user_id = get_current_user()
    all_keys = key_storage.get_all_user_keys(user_id)
    return render_template('keys.html', keys=all_keys, user_id=user_id)

if __name__ == '__main__':
    print("🚀 Starting ML-Adaptive Secure File Storage System...")
    print("📊 ML Model will train on first run if not found")
    print("🌐 Open http://localhost:5000 in your browser")
    print("")
    print("💡 TIP: If you have old Phase 2 files, they will show with default ML values")
    print("💡 Upload new files to see real ML classification in action!")
    app.run(debug=True, port=5000)