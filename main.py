from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import requests

app = Flask(__name__)

# -------------------- Configuration --------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerable_api.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# -------------------- Database Models --------------------
class Object(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# -------------------- Initialization --------------------
@app.before_first_request
def create_user():
    existing_user = User.query.filter_by(username='div').first()
    if not existing_user:
        hashed_password = bcrypt.generate_password_hash('Password').decode('utf-8')
        new_user = User(username='div', password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

# -------------------- OWASP Vulnerabilities --------------------

# API1: Broken Object Level Authorization
@app.route('/api/objects/<int:object_id>', methods=['GET'])
def get_object(object_id):
    obj = Object.query.get(object_id)
    if obj:
        return jsonify({'object': obj.__dict__})
    else:
        return jsonify({'error': 'Object not found'}), 404

# API2: Broken Authentication (flawed password check logic)
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    user = User.query.filter_by(username=username).first()

    # ❗ Insecure: Using plaintext match instead of bcrypt
    if user and user.password == password:
        return jsonify({'message': 'Authentication successful'})
    else:
        return jsonify({'error': 'Authentication failed'}), 401

# API3: Broken Object Property Level Authorization
@app.route('/api/objects/<int:object_id>/update', methods=['PUT'])
def update_object(object_id):
    data = request.get_json()
    obj = Object.query.get(object_id)

    if not obj:
        return jsonify({'error': 'Object not found'}), 404

    for key, value in data.items():
        setattr(obj, key, value)

    db.session.commit()
    return jsonify({'message': 'Object updated successfully'})

# API4: Unrestricted Resource Consumption
@app.route('/api/resource-consuming-endpoint', methods=['GET'])
def resource_consuming_endpoint():
    while True:
        pass
    return jsonify({'message': 'Resource-consuming request in progress'})

# API5: Broken Function Level Authorization
@app.route('/api/admin-action', methods=['GET'])
def admin_action():
    username = request.headers.get('username')

    if not username:
        return jsonify({'error': 'Unauthorized'}), 401

    if username == 'admin':
        return jsonify({'message': 'Admin action performed successfully'})
    else:
        return jsonify({'error': 'Unauthorized'}), 401

# API6: Unrestricted Access to Sensitive Business Flows
@app.route('/api/sensitive-operation', methods=['POST'])
def sensitive_operation():
    username = request.headers.get('username')

    if not username:
        return jsonify({'error': 'Unauthorized'}), 401

    if username == 'admin':
        return jsonify({'message': 'Sensitive operation performed successfully'})
    else:
        return jsonify({'error': 'Unauthorized'}), 401

# API7 & API10: Unsafe Consumption of APIs (SSRF)
@app.route('/api/consume-external-resource', methods=['GET'])
def consume_external_resource():
    url = request.args.get('url')

    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400

    try:
        response = requests.get(url)
        data = response.text
        return jsonify({'data': data})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/third-party-api', methods=['GET'])
def third_party_api():
    user_input = request.args.get('user_input')
    
    if user_input:
        return jsonify({'message': f'Third-party API response: {user_input}'})
    else:
        return jsonify({'error': 'No data received from the third-party API'}), 400

# API8: Security Misconfiguration
@app.route('/api/exposed-endpoint', methods=['GET'])
def exposed_endpoint():
    server_ip = "192.168.0.123"
    local_file = "/etc/passwd"
    
    return jsonify({
        'message': 'This is an exposed endpoint.',
        'server_ip': server_ip,
        'local_file': local_file
    })

# API9: Improper Inventory Management
@app.route('/api/public-endpoint', methods=['GET'])
def public_endpoint():
    return jsonify({'message': 'This is a public endpoint.'})

@app.route('/api/secure-endpoint', methods=['GET'])
def secure_endpoint():
    return jsonify({'message': 'This is a secure endpoint.'})

@app.route('/api/deprecated-endpoint', methods=['GET'])
def deprecated_endpoint():
    return jsonify({'message': 'This is a deprecated endpoint.'})

@app.route('/api/debug-endpoint', methods=['GET'])
def debug_endpoint():
    return jsonify({'message': 'This is a debug endpoint.'})

# -------------------- Main --------------------
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
