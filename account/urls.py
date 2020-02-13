from django.urls import path

from account.views import LoginAPIView, LogoutAPIView, RegisterAPIView, ProfileAPIView, PasswordResetAPIView, \
    PasswordResetConfirmAPIView, PasswordResetConfirmView

urlpatterns = [
    path('login/', LoginAPIView.as_view()),
    path('logout/', LogoutAPIView.as_view()),
    path('register/', RegisterAPIView.as_view()),
    path('profile/', ProfileAPIView.as_view()),
    path('password/reset/', PasswordResetAPIView.as_view()),
    path('password/reset/confirm/', PasswordResetConfirmAPIView.as_view()),
    path('password/reset/confirm/<uid>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
