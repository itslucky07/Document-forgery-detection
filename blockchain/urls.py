from django.urls import path
from . import views

urlpatterns = [
    path("sign-document/", views.sign_document, name="sign_document"),
    path("verify-document/", views.verify_document, name="verify_document"),
]
