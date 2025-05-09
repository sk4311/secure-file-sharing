from django.urls import path
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('signup/', RegisterView.as_view(), name='signup'),
    path('verify/<uidb64>/<token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('upload/', FileUploadView.as_view(), name='file-upload'),
    path('files/', UploadedFilesView.as_view(), name='list-uploaded-files'),
    path('file/download-url/<int:file_id>/', GenerateDownloadURLView.as_view(), name='generate-download-url'),
    path('file/download/<int:file_id>/<str:token>/', FileDownloadView.as_view(), name='download-file'),
]
