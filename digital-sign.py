import hashlib
import json
import time
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, 
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
import base64
from flask import Flask, request, jsonify, render_template_string, session
import tempfile

# Blockchain classes
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
        
    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        
    def create_genesis_block(self):
        return Block(0, time.time(), "Genesis Block", "0")
    
    def get_latest_block(self):
        return self.chain[-1]
    
    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)
    
    def find_document_record(self, document_id):
        """Find all records for a specific document"""
        records = []
        for block in self.chain:
            if isinstance(block.data, dict) and block.data.get("document_id") == document_id:
                records.append(block)
        return records

class DocumentVerifier:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.key_store_dir = os.path.join(os.getcwd(), "keys")
        os.makedirs(self.key_store_dir, exist_ok=True)
        
    def generate_keypair(self, signer_id):
        """Generate a new RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Save keys to files
        private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        
        # Save keys to files
        with open(os.path.join(self.key_store_dir, f"{signer_id}_private.pem"), "wb") as f:
            f.write(private_key_pem)
        
        with open(os.path.join(self.key_store_dir, f"{signer_id}_public.pem"), "wb") as f:
            f.write(public_key_pem)
        
        return private_key, public_key
    
    def load_keys(self, signer_id):
        """Load keys for a specific signer"""
        try:
            with open(os.path.join(self.key_store_dir, f"{signer_id}_private.pem"), "rb") as f:
                private_key_data = f.read()
                private_key = load_pem_private_key(private_key_data, password=None)
            
            with open(os.path.join(self.key_store_dir, f"{signer_id}_public.pem"), "rb") as f:
                public_key_data = f.read()
                public_key = load_pem_public_key(public_key_data)
                
            return private_key, public_key
        except Exception as e:
            print(f"Error loading keys: {e}")
            return None, None
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def sign_document(self, file_path, document_id, signer_id):
        """Sign a document and record it on the blockchain"""
        # Load keys
        private_key, public_key = self.load_keys(signer_id)
        if not private_key:
            return None, "Failed to load keys"
            
        # Calculate document hash
        document_hash = self.calculate_file_hash(file_path)
        
        # Create digital signature
        signature = private_key.sign(
            document_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Encode signature as base64
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        # Prepare blockchain record
        document_record = {
            "document_id": document_id,
            "document_hash": document_hash,
            "signer_id": signer_id,
            "signature": signature_b64,
            "timestamp": time.time(),
            "filename": os.path.basename(file_path)
        }
        
        # Add to blockchain
        new_block = Block(
            index=len(self.blockchain.chain),
            timestamp=time.time(),
            data=document_record,
            previous_hash=self.blockchain.get_latest_block().hash
        )
        self.blockchain.add_block(new_block)
        
        return document_hash, signature_b64
    
    def verify_document(self, file_path, document_id):
        """Verify if a document is authentic and unaltered"""
        # Calculate current hash
        current_hash = self.calculate_file_hash(file_path)
        
        # Get the blockchain record
        records = self.blockchain.find_document_record(document_id)
        
        if not records:
            return False, "Document not found in blockchain records"
        
        # Get the most recent record
        latest_record = records[-1]
        original_hash = latest_record.data["document_hash"]
        signature_b64 = latest_record.data["signature"]
        signer_id = latest_record.data["signer_id"]
        
        # Check if document hash matches original
        if current_hash != original_hash:
            return False, "Document has been modified (hash mismatch)"
        
        # Load public key
        _, public_key = self.load_keys(signer_id)
        if not public_key:
            return False, f"Failed to load public key for signer {signer_id}"
        
        # Verify signature
        try:
            signature = base64.b64decode(signature_b64)
            public_key.verify(
                signature,
                original_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True, "Document is authentic and unaltered"
        except Exception as e:
            return False, f"Signature verification failed: {str(e)}"

# Create Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize blockchain and document verifier
blockchain = Blockchain()
doc_verifier = DocumentVerifier(blockchain)

# HTML template with improved UI
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Blockchain Document Verification</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            background-color: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
        }
        .tab {
            padding: 10px 20px;
            background-color: #ddd;
            cursor: pointer;
            border-radius: 5px 5px 0 0;
            margin-right: 5px;
        }
        .tab.active {
            background-color: #fff;
            font-weight: bold;
        }
        .section {
            display: none;
            padding: 20px;
            background-color: #fff;
            border-radius: 0 5px 5px 5px;
            margin-bottom: 20px;
        }
        .section.active {
            display: block;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="file"] {
            width: 100%;
            padding: 8px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
        }
        button:hover {
            background-color: #45a049;
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 4px;
        }
        .success {
            background-color: #dff0d8;
            color: #3c763d;
        }
        .error {
            background-color: #f2dede;
            color: #a94442;
        }
        .saved-values {
            background-color: #e3f2fd;
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        .saved-values p {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Blockchain Document Verification System</h1>
        
        <div class="tabs">
            <div class="tab" onclick="showTab('generate')" id="generateTab">Generate Keys</div>
            <div class="tab" onclick="showTab('sign')" id="signTab">Sign Document</div>
            <div class="tab" onclick="showTab('verify')" id="verifyTab">Verify Document</div>
        </div>
        
        {% if saved_signer_id %}
        <div class="saved-values">
            <p><strong>Current Official ID:</strong> {{ saved_signer_id }}</p>
        </div>
        {% endif %}
        
        <div class="section" id="generateSection">
            <h2>Generate Keys for Official</h2>
            <form action="/generate-keys" method="post">
                <label for="signer_id">Official ID:</label>
                <input type="text" id="signer_id" name="signer_id" value="{{ saved_signer_id }}" required>
                <button type="submit">Generate Keys</button>
            </form>
        </div>
        
        <div class="section" id="signSection">
            <h2>Sign Document</h2>
            <form action="/sign-document" method="post" enctype="multipart/form-data">
                <label for="document">Select Document:</label>
                <input type="file" id="document" name="document" required>
                <label for="sign_document_id">Document ID:</label>
                <input type="text" id="sign_document_id" name="document_id" value="{{ saved_document_id }}" required>
                {% if saved_signer_id %}
                <input type="hidden" name="signer_id" value="{{ saved_signer_id }}">
                {% else %}
                <label for="sign_signer_id">Official ID:</label>
                <input type="text" id="sign_signer_id" name="signer_id" required>
                {% endif %}
                <button type="submit">Sign Document</button>
            </form>
        </div>
        
        <div class="section" id="verifySection">
            <h2>Verify Document</h2>
            <form action="/verify-document" method="post" enctype="multipart/form-data">
                <label for="verify_document">Select Document:</label>
                <input type="file" id="verify_document" name="document" required>
                <label for="verify_document_id">Document ID:</label>
                <input type="text" id="verify_document_id" name="document_id" value="{{ saved_document_id }}" required>
                <button type="submit">Verify Document</button>
            </form>
        </div>
        
        {% if result %}
        <div class="result {{ 'success' if success else 'error' }}">
            <h3>Result:</h3>
            <p>{{ result }}</p>
        </div>
        {% endif %}
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all sections
            document.querySelectorAll('.section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Remove active class from tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected section and activate tab
            document.getElementById(tabName + 'Section').classList.add('active');
            document.getElementById(tabName + 'Tab').classList.add('active');
            
            // Store active tab in localStorage
            localStorage.setItem('activeTab', tabName);
        }
        
        // On page load, set active tab (default to generate or restore from localStorage)
        document.addEventListener('DOMContentLoaded', function() {
            const activeTab = localStorage.getItem('activeTab') || 'generate';
            showTab(activeTab);
            
            {% if active_tab %}
            showTab('{{ active_tab }}');
            {% endif %}
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(
        TEMPLATE, 
        result=None, 
        success=None, 
        saved_signer_id=session.get('signer_id', ''),
        saved_document_id=session.get('document_id', ''),
        active_tab=None
    )

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    signer_id = request.form.get('signer_id')
    if not signer_id:
        return render_template_string(
            TEMPLATE, 
            result="Signer ID is required", 
            success=False,
            saved_signer_id=session.get('signer_id', ''),
            saved_document_id=session.get('document_id', ''),
            active_tab='generate'
        )
    
    try:
        # Save signer ID to session
        session['signer_id'] = signer_id
        
        doc_verifier.generate_keypair(signer_id)
        return render_template_string(
            TEMPLATE, 
            result=f"Keys generated successfully for {signer_id}", 
            success=True,
            saved_signer_id=signer_id,
            saved_document_id=session.get('document_id', ''),
            active_tab='generate'
        )
    except Exception as e:
        return render_template_string(
            TEMPLATE, 
            result=f"Error generating keys: {str(e)}", 
            success=False,
            saved_signer_id=session.get('signer_id', ''),
            saved_document_id=session.get('document_id', ''),
            active_tab='generate'
        )

@app.route('/sign-document', methods=['POST'])
def sign_document():
    if 'document' not in request.files:
        return render_template_string(
            TEMPLATE, 
            result="No document uploaded", 
            success=False,
            saved_signer_id=session.get('signer_id', ''),
            saved_document_id=session.get('document_id', ''),
            active_tab='sign'
        )
    
    document_file = request.files['document']
    document_id = request.form.get('document_id')
    signer_id = request.form.get('signer_id', session.get('signer_id', ''))
    
    if not document_file or not document_id or not signer_id:
        return render_template_string(
            TEMPLATE, 
            result="Document, Document ID, and Signer ID are required", 
            success=False,
            saved_signer_id=session.get('signer_id', ''),
            saved_document_id=session.get('document_id', ''),
            active_tab='sign'
        )
    
    # Save document ID to session
    session['document_id'] = document_id
    
    # Save uploaded file temporarily
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    document_file.save(temp_file.name)
    temp_file.close()
    
    try:
        document_hash, signature = doc_verifier.sign_document(temp_file.name, document_id, signer_id)
        os.unlink(temp_file.name)  # Delete temp file
        
        if not document_hash:
            return render_template_string(
                TEMPLATE, 
                result=signature,  # Error message
                success=False,
                saved_signer_id=signer_id,
                saved_document_id=document_id,
                active_tab='sign'
            )
        
        return render_template_string(
            TEMPLATE, 
            result=f"Document signed successfully. Hash: {document_hash[:15]}...", 
            success=True,
            saved_signer_id=signer_id,
            saved_document_id=document_id,
            active_tab='sign'
        )
    except Exception as e:
        os.unlink(temp_file.name)  # Delete temp file
        return render_template_string(
            TEMPLATE, 
            result=f"Error signing document: {str(e)}", 
            success=False,
            saved_signer_id=signer_id,
            saved_document_id=document_id,
            active_tab='sign'
        )

@app.route('/verify-document', methods=['POST'])
def verify_document():
    if 'document' not in request.files:
        return render_template_string(
            TEMPLATE, 
            result="No document uploaded", 
            success=False,
            saved_signer_id=session.get('signer_id', ''),
            saved_document_id=session.get('document_id', ''),
            active_tab='verify'
        )
    
    document_file = request.files['document']
    document_id = request.form.get('document_id')
    
    if not document_file or not document_id:
        return render_template_string(
            TEMPLATE, 
            result="Document and Document ID are required", 
            success=False,
            saved_signer_id=session.get('signer_id', ''),
            saved_document_id=session.get('document_id', ''),
            active_tab='verify'
        )
    
    # Save document ID to session
    session['document_id'] = document_id
    
    # Save uploaded file temporarily
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    document_file.save(temp_file.name)
    temp_file.close()
    
    try:
        is_valid, message = doc_verifier.verify_document(temp_file.name, document_id)
        os.unlink(temp_file.name)  # Delete temp file
        
        return render_template_string(
            TEMPLATE, 
            result=message, 
            success=is_valid,
            saved_signer_id=session.get('signer_id', ''),
            saved_document_id=document_id,
            active_tab='verify'
        )
    except Exception as e:
        os.unlink(temp_file.name)  # Delete temp file
        return render_template_string(
            TEMPLATE, 
            result=f"Error verifying document: {str(e)}", 
            success=False,
            saved_signer_id=session.get('signer_id', ''),
            saved_document_id=document_id,
            active_tab='verify'
        )

if __name__ == "__main__":
    # Create a demo official key pair
    doc_verifier.generate_keypair("DEMO-OFFICIAL-001")
    print("Demo keys generated for DEMO-OFFICIAL-001")
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)