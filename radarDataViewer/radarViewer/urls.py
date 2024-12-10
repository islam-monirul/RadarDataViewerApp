from django.urls import path
from .views import *

urlpatterns = [
    path('api/upload/', upload_and_process_file, name='upload_sort_file'),
    path('api/login/', login),
    path('api/register/', register),
    path('api/update/', update_user),
    path('api/test_token/', test_token),
]
