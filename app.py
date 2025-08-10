from flask import Flask,render_template, request, redirect,url_for, flash, jsonify
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask import session,abort
from werkzeug.utils import secure_filename
import PyPDF2
import uuid


# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')


# MySQL Config
app.config['MYSQL_HOST'] = os.getenv('DB_HOST')
app.config['MYSQL_USER'] = os.getenv('DB_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('DB_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('DB_NAME')
app.config['MYSQL_PORT'] = int(os.getenv('DB_PORT', 3306))

mysql = MySQL(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET'])
def upload_form():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('upload.html')

ALLOWED_EXTENSIONS = {'txt', 'pdf'}
UPLOAD_FOLDER = 'uploads/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    user_id = get_jwt_identity()

    if 'file' not in request.files:
        return jsonify({"msg": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"msg": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"msg": "File type not allowed, only .txt and .pdf"}), 400

    filename = file.filename
    unique_filename = f"{uuid.uuid4().hex}_{secure_filename(filename)}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(filepath)

    extracted_text = ""
    if unique_filename.endswith('.txt'):
        with open(filepath, 'r', encoding='utf-8') as f:
            extracted_text = f.read()
    elif unique_filename.endswith('.pdf'):
        extracted_text = extract_text_from_pdf(filepath)

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            INSERT INTO documents (user_id, title, file_name, content)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, file.filename, filepath, extracted_text)
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        return jsonify({"msg": "Database error", "error": str(e)}), 500

    return jsonify({"msg": "File uploaded successfully"}), 201

def extract_text_from_pdf(pdf_path):
    text = ""
    try:
        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                try:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text
                except Exception as e:
                    # ignore extraction error for this page
                    pass
    except Exception as e:
        print(f"PDF read error: {e}")
    return text



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"msg": "Email and password required"}), 400

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, password FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

        if not user:
            return jsonify({"msg": "Invalid credentials"}), 401

        user_id, pw_hash = user[0], user[1]
        if not bcrypt.check_password_hash(pw_hash, password):
            return jsonify({"msg": "Invalid credentials"}), 401

        access_token = create_access_token(identity=str(user_id))

        session['user_id'] = user_id
        session['email'] = email

        return jsonify(access_token=access_token), 200
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # data = request.get_json()
        data = request.form
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"msg": "Email and password required"}), 400

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        if user:
            return jsonify({"msg": "User already exists"}), 400

        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        cur.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, pw_hash))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    
    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True, port=8000)
