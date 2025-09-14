import os
from flask import Flask, request, render_template, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Configuration
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page with upload form"""
    # List all uploaded files
    files = []
    if os.path.exists(UPLOAD_FOLDER):
        files = os.listdir(UPLOAD_FOLDER)
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # Secure the filename to prevent path traversal attacks
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the file
        file.save(file_path)
        flash(f'File "{filename}" uploaded successfully!')
        return render_template('success.html', filename=filename)
    else:
        flash('File type not allowed')
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    """Handle file download"""
    try:
        # Secure the filename
        filename = secure_filename(filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            flash('File not found')
            return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error downloading file: {str(e)}')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)