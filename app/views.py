from django.shortcuts import render
from .forms import ImageDetectionForm
import cv2
import numpy as np
from django.conf import settings
import os
from . utility import detect_aadhaar_forgery, analyze_image_difference, bank_statement_main
from .forms import CSVUploadForm
import pandas as pd
import openai
# Create your views here.


def upload_image(request):
    if request.method == "POST":
        form = ImageDetectionForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_image = form.save()
            image_path = os.path.join(settings.MEDIA_ROOT, str(uploaded_image.image))
            
            # Run forgery detection
            if uploaded_image.type_doc == "Aadhar":
                image_path_og_aadhar = os.path.join(os.path.dirname(__file__), "og.png")
            elif uploaded_image.type_doc == "PAN":
                image_path_og_aadhar = os.path.join(os.path.dirname(__file__), "pan.png")

            forgery_result = detect_aadhaar_forgery(image_path_og_aadhar, image_path)
            analyze_image_difference(image_path_og_aadhar, image_path)
            # llm_response = get_llm_judgment(forgery_result)
            return render(request, "result.html", {"forgery": forgery_result})
    else:
        form = ImageDetectionForm()
    
    return render(request, "index.html", {"form": form})

def upload_csv(request):
    if request.method == 'POST':
        form = CSVUploadForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            csv_file = request.FILES['file']
            
            # Read CSV using pandas
            df = pd.read_csv(csv_file)
            # csv_data = df.to_html(classes="table table-bordered table-striped")
            csv_data = bank_statement_main(df)
            print(csv_data)
            return render(request, 'csv_result.html', {'csv_data': csv_data})
    else:
        form = CSVUploadForm()
    
    return render(request, 'csv_upload.html', {'form': form})