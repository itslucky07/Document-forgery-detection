from django import forms
from .models import ImageDetection
from .models import UploadedCSV

class ImageDetectionForm(forms.ModelForm):
    class Meta:
        model = ImageDetection
        fields = ['image', 'type_doc']

class CSVUploadForm(forms.ModelForm):
    class Meta:
        model = UploadedCSV
        fields = ['file']
