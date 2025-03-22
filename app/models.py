from django.db import models

class ImageDetection(models.Model):
    image = models.ImageField(upload_to='doc_img/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    response_img = models.ImageField(upload_to='doc_img_compare/')
    DOC_CHOICES = {
        "Aadhar": "Aadhar Card",
        "PAN": "Pan Card",
    }
    type_doc = models.CharField(max_length=150, choices=DOC_CHOICES)

class UploadedCSV(models.Model):
    file = models.FileField(upload_to='csv_uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"CSV File - {self.file.name}"