from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .serializers import RegisterSerializer, LoginSerializer
from .tokens import email_verification_token
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import *
from .serializers import FileUploadSerializer
from django.http import FileResponse
from django.core.exceptions import PermissionDenied

User = get_user_model()

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = email_verification_token.make_token(user)
            verification_url = request.build_absolute_uri(
                reverse('verify-email', kwargs={'uidb64': uid, 'token': token})
            )
            send_mail(
                subject='Verify your email',
                message=f'Click here to verify: {verification_url}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
            )
            return Response({'message': 'User created. Verification email sent.', 'url': verification_url})
        return Response(serializer.errors, status=400)

class VerifyEmailView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid user.'}, status=400)

        if email_verification_token.check_token(user, token):
            user.is_verified = True
            user.is_active = True
            user.save()
            return Response({'message': 'Email verified successfully.'})
        return Response({'error': 'Invalid token.'}, status=400)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)

            if user is not None:
                if user.is_verified:
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'message': 'Login successful.',
                        'role': user.role,
                        'access': str(refresh.access_token),
                        'refresh': str(refresh)
                    }, status=200)
                return Response({'error': 'Email not verified.'}, status=403)
            return Response({'error': 'Invalid credentials.'}, status=401)
        return Response(serializer.errors, status=400)


class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if request.user.role != 'ops':
            return Response({'error': 'Only Ops users can upload files.'}, status=403)
        
        serializer = FileUploadSerializer(data=request.data)
        if serializer.is_valid():
            file_upload = serializer.save(uploaded_by=request.user)
            file_upload.generate_download_token()  # Generate token for secure download
            return Response({
                'file_id': file_upload.id,
                'file_url': file_upload.file.url
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=400)
    
    
    

class UploadedFilesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Only allow Client users to view the files
        if request.user.role != 'client':
            return Response({'error': 'Only Client users can view the uploaded files.'}, status=403)

        # Get all files uploaded by Ops users
        files = FileUpload.objects.all()
        serializer = FileUploadSerializer(files, many=True)
        return Response(serializer.data)
    
class GenerateDownloadURLView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, file_id):
        try:
            file_upload = FileUpload.objects.get(id=file_id)
        except FileUpload.DoesNotExist:
            return Response({"error": "File not found."}, status=404)

        # Only allow Client users to generate download URLs
        if request.user.role != 'client':
            return Response({"error": "Only Client users can generate download URLs."}, status=403)

        # Generate a unique download token for the file if not already present
        if not file_upload.download_token:
            file_upload.generate_download_token()

        # Create a secure download URL
        download_url = request.build_absolute_uri(
            reverse('download-file', kwargs={'file_id': file_upload.id, 'token': file_upload.download_token})
        )

        return Response({"download_url": download_url})
    
class FileDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, file_id, token):
        try:
            file_upload = FileUpload.objects.get(id=file_id)
        except FileUpload.DoesNotExist:
            return Response({"error": "File not found."}, status=404)

        # Check if the provided token matches the file's token
        if file_upload.download_token != token:
            return Response({"error": "Invalid or expired token."}, status=400)

        # Only Client users can download the file
        if request.user.role != 'client':
            raise PermissionDenied("You do not have permission to download this file.")

        # Provide the file as a response
        file_path = file_upload.file.path
        return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=file_upload.file.name)