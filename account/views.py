from django.contrib.auth import get_user_model
from django.views import View
from rest_framework.authtoken.models import Token
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from account.permissions import IsOwnerOnly
from account.serializers import LoginSerializer, RegisterSerializer, ProfileSerializer, PasswordResetSerializer, \
    PasswordResetConfirmSerializer

User = get_user_model()


class LoginAPIView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({'key': user.auth_token.key, 'message': f'{user.username}님 반갑습니다.'})


class LogoutAPIView(GenericAPIView):
    def post(self, request):
        user = request.user
        user.auth_token.delete()

        return Response({'message': f'{user.username}님 안녕히가세요.'})


class RegisterAPIView(GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({'key': user.auth_token.key, 'message': f'{user.username}님 가입을 축하드립니다.'})


class ProfileAPIView(GenericAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated, IsOwnerOnly]

    def get(self, request):
        serializer = self.get_serializer(request.user)

        return Response(serializer.data)

    def patch(self, request):
        serializer = self.get_serializer(request.user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({'message': '수정이 완료되었습니다.'})


class PasswordResetAPIView(GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({'message': f'{user.email}로 비밀번호 초기화 주소가 전송되었습니다.'})


class PasswordResetConfirmAPIView(GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({'message': f'{user.username}님의 비밀번호가 재설정되었습니다.'})


class PasswordResetConfirmView(View):
    pass
