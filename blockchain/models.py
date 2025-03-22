from django.db import models

class DocumentRecord(models.Model):
    document_id = models.CharField(max_length=100, unique=True)
    document_hash = models.TextField()
    signer_id = models.CharField(max_length=100)
    signature = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    filename = models.CharField(max_length=255)
    
    def __str__(self):
        return f"{self.filename} - {self.signer_id}"
