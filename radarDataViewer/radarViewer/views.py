"""
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from .models import RadarFile
from .utils import process_sort_file, create_error_response
import logging

logger = logging.getLogger(__name__)

@csrf_exempt
@api_view(['POST'])
def upload_and_process_file(request):
    try:
        logger.debug(f"Request method: {request.method}")
        logger.debug(f"Request FILES: {request.FILES}")
        file = request.FILES.get('file')
        if not file:
            return create_error_response("No file provided. Please upload a .SORT file.", 400)

        if not file.name.lower().endswith('.sort'):
            return create_error_response("Invalid file type. Please upload a .SORT file.", 400)

        radar_file = RadarFile(file=file)
        radar_file.save()

        logger.debug(f"Saved file at: {radar_file.file.path}")

        radar_data, metadata, images = process_sort_file(radar_file.file.path)
        if radar_data is None or metadata is None or images is None:
            return create_error_response("Failed to process the .SORT file. Ensure the file format is correct.", 500)

        return JsonResponse({
            "message": "File processed successfully",
            "metadata": metadata,
            "images": images
        }, status=200)

    except Exception as e:
        logger.error(f"Unexpected error during file processing: {e}")
        return create_error_response("An unexpected error occurred while processing the file.", 500)
"""
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view

from radarDataViewer.serializers import UpdateUserSerializer, UserSerializer
from .models import RadarFile
from .utils import process_sort_file, create_error_response
import logging
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

logger = logging.getLogger(__name__)

@csrf_exempt
@api_view(['POST'])
def upload_and_process_file(request):
    try:
        logger.debug(f"Request method: {request.method}")
        logger.debug(f"Request FILES: {request.FILES}")
        file = request.FILES.get('file')
        if not file:
            return create_error_response("No file provided. Please upload a .SORT file.", 400)

        if not file.name.lower().endswith('.sort'):
            return create_error_response("Invalid file type. Please upload a .SORT file.", 400)

        # Save the uploaded file
        radar_file = RadarFile(file=file)
        radar_file.save()

        logger.debug(f"Saved file at: {radar_file.file.path}")

        # Process the .SORT file
        metadata, images, cartesian_data = process_sort_file(radar_file.file.path)
        
        if metadata is None or images is None:
            return create_error_response("Failed to process the .SORT file. Ensure the file format is correct.", 500)

        # Prepare the response
        response_data = {
            "message": "File processed successfully",
            "metadata": metadata,
            "images": images,  # Base64 images
        }

        # Include Cartesian data only if available
        if cartesian_data:
            response_data["cartesian_data"] = {
                "x": cartesian_data["x"].tolist(),  # Convert NumPy array to list
                "y": cartesian_data["y"].tolist(),
            }

        return JsonResponse(response_data, status=200)

    except Exception as e:
        logger.error(f"Unexpected error during file processing: {e}")
        return create_error_response("An unexpected error occurred while processing the file.", 500)
    
@api_view(['POST'])
def login(request):
    user = get_object_or_404(User, username=request.data['username'])
    if not user.check_password(request.data['password']):
        return Response("missing user", status=status.HTTP_404_NOT_FOUND)
    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(user)
    return Response({'token': token.key, 'user': serializer.data})

@api_view(['POST'])
def register(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        user = User.objects.get(username=request.data['username'])
        user.set_password(request.data['password'])
        user.save()
        token = Token.objects.create(user=user)
        return Response({'token': token.key, 'user': serializer.data, "message" : "User created Succesfully"})
    return Response(serializer.errors, status=status.HTTP_200_OK)

########################## Not working
########################## Not working
########################## Not working
@api_view(['PUT'])
def update_user(request):
    user = request.user
    serializer = UpdateUserSerializer(user, data=request.data)
    if serializer.is_valid():
        serializer.save()
        # user = User.objects.get(username=request.data['username'])
        # user.set_password(request.data['password'])
        # user.save()
        # token = Token.objects.create(user=user)
        return Response({'user': serializer.data, "message" : "Updated User info Succesfully"})
    return Response(serializer.errors, status=status.HTTP_200_OK)
########################## Not working
########################## Not working
########################## Not working

@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed for {}".format(request.user.email))