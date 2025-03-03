from django.urls import path
from .views import *

urlpatterns = [
    path('register', Register.as_view(), name='register'),
    path('send-verification-code', SendVerificationCode.as_view(), name='send_verification_code'),
    path('send-verification-code-reg', RegisterSendVerificationCode.as_view(), name='send_verification_code-reg'),
    path('verify-email', VerifyEmail.as_view(), name='verify_email'),
    path('login', Login.as_view(), name='login'),
    path('verify-handshake', VerifyHandshake.as_view(), name='verify_handshake'),
    path('refresh-token', RefreshTokenView.as_view(), name='refresh-token'),
    path('logout', Logout.as_view(), name='logout'),
    path('categories', CategoryAPIView.as_view(), name='categories'),
    path('orders', OrderAPIView.as_view(), name='orders'),
    path('setup-2fa', Setup2FAView.as_view(), name='setup-2fa'),
    path('verify-setup-2fa', VerifySetup2FAView.as_view(), name='verify-setup-2fa'),
    path('verify-2fa', Verify2FAView.as_view(), name='verify-2fa'),
    path('disable-2fa', Disable2FAView.as_view(), name='disable-2fa'),
    path('car-parts', CarPartAPIView.as_view(), name='car-parts'),
    path('car-parts/<int:part_id>/', CarPartAPIView.as_view(), name='car-part-detail'),
    path('seller-accounts', SellerAccountsAPIView.as_view(), name='seller-accounts'),
    path('verify-password', VerifyPasswordView.as_view(), name='verify-password'),
    path('seller-orders', SellerSoldOrdersAPIView.as_view(), name='seller-orders'),
    path('reset-password', ResetPasswordView.as_view(), name='reset-password'),

]
