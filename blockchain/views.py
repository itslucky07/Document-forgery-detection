import hashlib
import base64
import time
from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import DocumentRecord
from django.core.files.storage import FileSystemStorage

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def sign_document(request):
    if request.method == "POST" and request.FILES.get("document"):
        file = request.FILES["document"]
        document_id = request.POST.get("document_id")
        signer_id = request.POST.get("signer_id")

        fs = FileSystemStorage()
        filename = fs.save(file.name, file)
        file_path = fs.path(filename)

        document_hash = calculate_file_hash(file_path)
        signature = base64.b64encode(document_hash.encode()).decode()

        DocumentRecord.objects.create(
            document_id=document_id,
            document_hash=document_hash,
            signer_id=signer_id,
            signature=signature,
            filename=file.name
        )

        return JsonResponse({"message": "Document signed!", "document_hash": document_hash})
    return render(request, "sign.html")

def verify_document(request):
    if request.method == "POST" and request.FILES.get("document"):
        file = request.FILES["document"]
        document_id = request.POST.get("document_id")

        fs = FileSystemStorage()
        filename = fs.save(file.name, file)
        file_path = fs.path(filename)

        document_hash = calculate_file_hash(file_path)
        record = DocumentRecord.objects.filter(document_id=document_id).last()

        if record and record.document_hash == document_hash:
            return JsonResponse({"message": "Document is authentic!", "status": "success"})
        return JsonResponse({"message": "Document is modified!", "status": "error"})
    
    return render(request, "verify.html")
