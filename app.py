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
from openai import OpenAI
import time
from datetime import datetime

load_dotenv()
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))


# Load environment variables from .env

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

@app.route('/ask', methods=['GET'])
def ask_form():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, title FROM documents WHERE user_id=%s ORDER BY upload_time DESC", (user_id,))
        document_list = cur.fetchall()
        cur.close()
    except Exception as e:
        document_list = []
        # Optionally log the error here

    return render_template('ask.html', documents=document_list)

@app.route('/ask', methods=['POST'])
@jwt_required()
def ask():
    user_id = get_jwt_identity()
    data = request.get_json()

    question = data.get('question')
    document_id = data.get('document_id')

    if not question or not document_id:
        return jsonify({"msg": "Question and document_id are required"}), 400

    # Fetch document content for the user
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT content FROM documents WHERE id=%s AND user_id=%s", (document_id, user_id))
        row = cur.fetchone()
        cur.close()

        if not row:
            return jsonify({"msg": "Document not found"}), 404

        document_content = row[0]

    except Exception as e:
        return jsonify({"msg": "DB error", "error": str(e)}), 500

    # Prepare the prompt (you can customize this)
    # prompt = f"Based on the following document, answer the question:\n\n{document_content}\n\nQuestion: {question}\nAnswer:"

    # Prepare conversation for Chat API
    messages = [
        {"role": "system", "content": "You are an assistant that only answers questions using the provided document text. If the answer is not found in the document, say 'I cannot find the answer in the provided text.'"},
        {"role": "user", "content": f"Document:\n{document_content}\n\nQuestion: {question}"}
    ]

    try:
        start_time = time.time()
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=512,
            temperature=0.0
        )
        latency = time.time() - start_time
        answer = response.choices[0].message.content.strip()
        tokens_used = response.usage.total_tokens if response.usage else 0
    except Exception as e:
        return jsonify({"msg": "OpenAI API error", "error": str(e)}), 500

    # Save Q&A history
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            INSERT INTO qa_history (user_id, document_id, question, answer, latency_ms, tokens_used,asked_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (user_id, document_id, question, answer, latency, tokens_used, datetime.now())
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        return jsonify({"msg": "DB save error", "error": str(e)}), 500

    return jsonify({"answer": answer, "latency": latency, "tokens_used": tokens_used})

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
            INSERT INTO documents (user_id, title, file_name, content,upload_time)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, file.filename, filepath, extracted_text, datetime.now())
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
