import os
from flask import Flask, request, render_template, send_file, flash, redirect, url_for, jsonify, session
from werkzeug.utils import secure_filename
import tempfile

# Import our new modules
from crypto_utils import crypto_manager
from key_storage import key_storage
from file_storage import file_storage

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Configuration
UPLOAD_FOLDER = 'encrypted_uploads'
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_current_user():
    """Get current user (simplified - use proper auth in production)"""
    return session.get('user_id', 'default_user')

@app.route('/')
def index():
    """Main page"""
    user_id = get_current_user()
    
    # Check if user has keys, if not generate them
    if not key_storage.has_user_keys(user_id):
        public_key, private_key = crypto_manager.generate_key_pair()
        key_storage.store_user_keys(public_key, private_key, user_id)
        flash(f'🔑 Generated new encryption keys for you!')
    
    # Get user's files
    user_files = file_storage.get_user_files(user_id)
    
    return render_template('index_encrypted.html', files=user_files, user_id=user_id)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle encrypted file upload"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if not (file and allowed_file(file.filename)):
        flash('File type not allowed')
        return redirect(url_for('index'))
    
    try:
        user_id = get_current_user()
        
        # Read file data
        file_data = file.read()
        original_filename = secure_filename(file.filename)
        
        # Get user's public key
        user_keys = key_storage.get_user_keys(user_id)
        public_key = user_keys['public_key']
        
        # Encrypt file
        encrypted_file_data, encrypted_aes_key = crypto_manager.encrypt_file(file_data, public_key)
        
        # Generate unique filename for storage
        encrypted_filename = f"enc_{user_id}_{len(file_storage.files)}.dat"
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        # Save encrypted file to disk
        with open(encrypted_filepath, 'w') as f:
            f.write(encrypted_file_data)
        
        # Store file metadata
        file_id = file_storage.store_file_info(
            encrypted_filename, 
            original_filename, 
            encrypted_aes_key, 
            len(file_data),
            user_id
        )
        
        flash(f'🔒 File "{original_filename}" uploaded and encrypted successfully!')
        return render_template('success_encrypted.html', 
                             filename=original_filename, 
                             file_id=file_id,
                             encrypted=True)
    
    except Exception as e:
        flash(f'❌ Encryption failed: {str(e)}')
        return redirect(url_for('index'))

@app.route('/download/<file_id>')
def download_file(file_id):
    """Handle encrypted file download"""
    try:
        user_id = get_current_user()
        
        # Get file metadata
        file_info = file_storage.get_file_info(file_id)
        if not file_info:
            flash('File not found')
            return redirect(url_for('index'))
        
        # Check if user owns the file
        if file_info['user_id'] != user_id:
            flash('Access denied')
            return redirect(url_for('index'))
        
        # Get user's private key
        user_keys = key_storage.get_user_keys(user_id)
        private_key = user_keys['private_key']
        
        # Read encrypted file
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_info['filename'])
        with open(encrypted_filepath, 'r') as f:
            encrypted_file_data = f.read()
        
        # Decrypt file
        decrypted_data = crypto_manager.decrypt_file(
            encrypted_file_data, 
            file_info['encrypted_aes_key'], 
            private_key
        )
        
        # Create temporary file for download
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

@app.route('/keys')
def show_keys():
    """Show user's encryption keys (for debugging)"""
    user_id = get_current_user()
    keys = key_storage.get_user_keys(user_id)
    return render_template('keys.html', keys=keys, user_id=user_id)

if __name__ == '__main__':
    app.run(debug=True, port=5000)