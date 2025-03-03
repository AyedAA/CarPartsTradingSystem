from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.utils.timezone import now, make_aware,timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64
from hashlib import sha256
from django.db.utils import IntegrityError
from .serializers import *
from django.db.models import Q
from django.core.paginator import Paginator
from django.db import transaction
from datetime import datetime
from django.shortcuts import get_object_or_404
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import re
from django.core.mail import send_mail
from django.core.cache import cache
from django.contrib.auth.hashers import make_password

SHARED_SECRET = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

class TokenHandler:

    @staticmethod
    def create_tokens(user):
        try:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return {
                'access_token': access_token,
                'refresh_token': str(refresh),
                'token_type': 'Bearer'
            }
        except Exception as e:
            raise Exception(f"Error creating tokens: {str(e)}")

    @staticmethod
    def verify_token(auth_header):
        if not auth_header or not auth_header.startswith('Bearer '):
            return None, Response({'error': 'Invalid authorization header'}, status=401)

        try:
            token = auth_header.split(' ')[1]
            decoded_token = AccessToken(token)

            user = User.objects.get(id=decoded_token['user_id'])

            return user, None

        except Exception as e:
            return None, Response({'error': str(e)}, status=401)

    @staticmethod
    def refresh_tokens(refresh_token_str):
        try:
            refresh = RefreshToken(refresh_token_str)
            user = User.objects.get(id=refresh['user_id'])

            new_access = str(refresh.access_token)

            return {
                'access_token': new_access,
                'refresh_token': refresh_token_str,
                'token_type': 'Bearer'
            }

        except Exception as e:
            raise Exception(f"Error refreshing tokens: {str(e)}")

class SendVerificationCode(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=400)

        if not User.objects.filter(email=email).exists():
            return Response({'error': 'This email is not registered'}, status=400)

        verification_code = str(secrets.randbelow(1000000)).zfill(6)

        cache_key = f'verification_code:{email}'
        cache.set(cache_key, verification_code, timeout=300)

        send_mail(
            subject="Verify Your Email",
            message=f"Your verification code is: {verification_code}",
            from_email="carpartapp0@gmail.com",
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({'message': 'Verification code sent to your email.'}, status=200)

class RegisterSendVerificationCode(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=400)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'This email is already registered'}, status=400)

        verification_code = str(secrets.randbelow(1000000)).zfill(6)

        cache_key = f'verification_code:{email}'
        cache.set(cache_key, verification_code, timeout=300)

        send_mail(
            subject="Verify Your Email for Registration",
            message=f"Your registration verification code is: {verification_code}",
            from_email="carpartapp0@gmail.com",
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({'message': 'Verification code sent to your email.'}, status=200)

class VerifyEmail(APIView):
    def post(self, request):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')

        if not email or not verification_code:
            return Response({'error': 'Email and verification code are required'}, status=400)

        cache_key = f'verification_code:{email}'
        stored_verification_code = cache.get(cache_key)

        if not stored_verification_code:
            return Response({'error': 'Verification code expired or invalid. Please request a new code.'}, status=400)

        if str(stored_verification_code) != str(verification_code):
            return Response({"error": "Invalid verification code"}, status=400)

        cache.delete(cache_key)

        return Response({'message': 'Email verified successfully.'}, status=200)


class Register(APIView):
    def post(self, request):
        """Register a new user"""
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                phone = request.data.get("phone")
                email = request.data.get("email")
                password = request.data.get("password")

                if not phone:
                    return Response({'error': 'Phone number is required'}, status=400)

                if not email:
                    return Response({'error': 'Email is required'}, status=400) # Ensure email is provided

                if not self._is_secure_password(password):
                    return Response({'error': 'Password must be at least 8 characters long, include an uppercase letter, lowercase letter, a number, and a special character.'}, status=400)

                with transaction.atomic():
                    user = User.objects.create_user(
                        username=serializer.validated_data['username'],
                        email=email,
                        password=password,
                        is_active=True
                    )

                    profile = UserProfile.objects.create(
                        user=user,
                        role="buyer",
                        phone=phone
                    )

                    tokens = TokenHandler.create_tokens(user)

                    response_data = {
                        **tokens,
                        'id': profile.pk,
                        'user': serializer.data,
                        'role': 'buyer'
                    }

                    response = Response(response_data, status=201)
                    response['Authorization'] = f'Bearer {tokens["access_token"]}'
                    response['Refresh-Token'] = tokens['refresh_token']
                    return response

            except IntegrityError:
                return Response({'error': 'Phone number already exists'}, status=400)
            except Exception as e:
                return Response({'error': str(e)}, status=400)

        return Response(serializer.errors, status=400)

    def _is_secure_password(self, password):
        """Check if the password is secure"""
        return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$', password))

class Login(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            user = authenticate(username=username, password=password)

            if user:
                try:
                    profile = UserProfile.objects.get(user=user)
                    server_challenge = secrets.token_hex(16)

                    response_data = {
                        '2fa_required': bool(profile.totp_secret),
                        'server_challenge': server_challenge,
                        'challenge_created_at': now().isoformat(),
                        'detail': '2FA required' if profile.totp_secret else 'Handshake initiated'
                    }

                    return Response(response_data, status=200)

                except UserProfile.DoesNotExist:
                    return Response({'error': 'User profile not found'}, status=404)

            return Response({'error': 'Invalid credentials'}, status=401)

        return Response(serializer.errors, status=400)

class VerifyHandshake(APIView):
    def post(self, request):
        """التحقق من استجابة العميل للمصافحة"""
        required_fields = [
            'server_challenge',
            'challenge_created_at',
            'client_response',
            'username'
        ]

        if not all(field in request.data for field in required_fields):
            return Response({'error': 'Missing required fields'}, status=400)

        try:
            challenge_time = datetime.fromisoformat(request.data['challenge_created_at'])
            if challenge_time.tzinfo is None:
                challenge_time = make_aware(challenge_time)

            if (now() - challenge_time).seconds > 300:
                return Response({'error': 'Challenge expired'}, status=400)

            expected_response = sha256(
                (request.data['server_challenge'] + SHARED_SECRET).encode()
            ).hexdigest()

            if request.data['client_response'] == expected_response:
                user = User.objects.get(username=request.data['username'])
                profile = UserProfile.objects.get(user=user)

                if profile.totp_secret and not request.data.get('totp_token'):
                    return Response({'error': '2FA token required'}, status=400)

                if profile.totp_secret:
                    totp = pyotp.TOTP(profile.totp_secret)
                    if not totp.verify(request.data['totp_token']):
                        return Response({'error': 'Invalid 2FA token'}, status=400)

                tokens = TokenHandler.create_tokens(user)

                response_data = {
                    **tokens,
                    'id': profile.pk,
                    'email': user.email,
                    'role': profile.role,
                    'detail': 'Authentication successful'
                }

                response = Response(response_data, status=200)
                response['Authorization'] = f'Bearer {tokens["access_token"]}'
                response['Refresh-Token'] = tokens['refresh_token']
                return response

            return Response({'error': 'Handshake failed'}, status=401)

        except Exception as e:
            return Response({'error': 'Verification failed'}, status=400)

class ResetPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')

        if not email or not new_password:
            return Response({'error': 'Email and new password are required'}, status=400)

        try:
            # Fetch user by email, handle the case of multiple users
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=404)
        except User.MultipleObjectsReturned:
            return Response({'error': 'Multiple users found with this email, please contact support'}, status=409)

        user.password = make_password(new_password)
        user.save()

        cache_key = f'password_reset_code:{email}'
        cache.delete(cache_key)

        return Response({'message': 'Password reset successfully.'}, status=200)

class RefreshTokenView(APIView):
    def post(self, request):
        """تحديث التوكن"""
        refresh_token = request.headers.get('Refresh-Token')
        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=400)

        try:
            new_tokens = TokenHandler.refresh_tokens(refresh_token)

            response = Response({
                **new_tokens,
                'detail': 'Token refresh successful'
            }, status=200)

            response['Authorization'] = f'Bearer {new_tokens["access_token"]}'
            response['Refresh-Token'] = new_tokens['refresh_token']
            return response

        except Exception as e:
            return Response({'error': 'Token refresh failed'}, status=400)

class Logout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """تسجيل الخروج"""
        try:
            response = Response({'detail': 'Logout successful'}, status=200)
            response.delete_cookie('auth_token')
            return response
        except Exception as e:
            return Response({'error': 'Logout failed'}, status=400)

class BaseAuthenticatedAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_user_from_token(self, request):
        """استخراج المستخدم من التوكن"""
        try:
            user = request.user
            profile = get_object_or_404(UserProfile, user=user)
            return profile, None
        except Exception:
            return None, Response({'error': 'Authentication failed'}, status=401)

class Setup2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """إعداد المصادقة الثنائية وإرسال رمز تحقق عبر البريد الإلكتروني"""
        user = request.user
        try:
            profile = UserProfile.objects.get(user=user)

            if not profile.totp_secret:
                totp_secret = pyotp.random_base32()
                profile.totp_secret = totp_secret
                profile.save()

            verification_code = str(secrets.randbelow(1000000)).zfill(6)
            profile.verification_code = verification_code
            profile.verification_code_created_at = now()
            profile.save()

            send_mail(
                subject="Your 2FA Verification Code",
                message=f"Your verification code is: {verification_code}",
                from_email="carpartapp0@gmail.com",
                recipient_list=[user.email],
                fail_silently=False,
            )

            return Response({
                "message": "Verification code sent to your email. Please verify to enable 2FA."
            }, status=200)

        except Exception as e:
            return Response({"error": f"Failed to setup 2FA: {str(e)}"}, status=400)

class VerifySetup2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """تأكيد رمز التحقق وتفعيل المصادقة الثنائية"""
        user = request.user
        verification_code = request.data.get('verification_code')

        if not verification_code:
            return Response({"error": "Verification code is required"}, status=400)

        try:
            profile = UserProfile.objects.get(user=user)

            if str(profile.verification_code) != str(verification_code):
                return Response({"error": "Invalid verification code"}, status=400)

            if (now() - profile.verification_code_created_at).seconds > 300:
                return Response({"error": "Verification code expired"}, status=400)

            profile.is_2fa_enabled = True
            profile.verification_code = None
            profile.verification_code_created_at = None
            profile.save()

            return Response({"message": "2FA enabled successfully"}, status=200)

        except Exception as e:
            return Response({"error": f"Failed to verify 2FA: {str(e)}"}, status=400)

class Verify2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """التحقق مما إذا كان لدى المستخدم مصادقة ثنائية وإرسال QR code عند تفعيلها"""
        try:
            profile = UserProfile.objects.get(user=request.user)  # ✅ التعديل هنا

            if not profile.is_2fa_enabled:
                return Response({"2fa_enabled": False}, status=200)

            totp = pyotp.TOTP(profile.totp_secret)
            otp_auth_url = totp.provisioning_uri(
                name=profile.user.email,
                issuer_name="MyPartsApp"
            )

            qr = qrcode.make(otp_auth_url)
            buffered = BytesIO()
            qr.save(buffered, format="PNG")
            qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

            return Response({
                "2fa_enabled": True,
                "qr_code": f"data:image/png;base64,{qr_base64}"
            }, status=200)

        except Exception as e:
            return Response({'error': f'Failed to retrieve 2FA information: {str(e)}'}, status=500)

class Disable2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """تعطيل المصادقة الثنائية"""
        try:
            profile = UserProfile.objects.get(user=request.user)

            if not profile.is_2fa_enabled:
                return Response({"error": "2FA not set up"}, status=400)

            profile.totp_secret = None
            profile.is_2fa_enabled = False

            profile.save()

            return Response({"detail": "2FA disabled successfully"}, status=200)

        except Exception as e:
            return Response({'error': f'2FA disable failed: {str(e)}'}, status=400)

class CategoryAPIView(BaseAuthenticatedAPIView, APIView):

    def post(self, request):
        """إضافة فئة جديدة (للمشرفين فقط)"""
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'success', 'category': serializer.data}, status=201)
        return Response({'status': 'error', 'errors': serializer.errors}, status=400)


    def get(self, request):
        """جلب جميع الفئات"""
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        categories_data = [
            {
                'id': category.id,
                'name': category.name,
                'photo': category.photo.url if category.photo else None,
            }
            for category in categories
        ]
        return Response({'status': 'success', 'categories': categories_data}, status=200)

    def put(self, request, category_id):
        """تحديث فئة (للمشرفين فقط)"""
        try:
            category = Category.objects.get(id=category_id)
            serializer = CategorySerializer(category, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'status': 'success', 'category': serializer.data}, status=200)
            return Response({'status': 'error', 'errors': serializer.errors}, status=400)
        except Category.DoesNotExist:
            return Response({'status': 'error', 'error': 'Category not found'}, status=404)

    def delete(self, request, category_id):
        """حذف فئة (للمشرفين فقط)"""
        try:
            category = Category.objects.get(id=category_id)
            category.delete()
            return Response({'status': 'success', 'message': 'Category deleted successfully'}, status=204)
        except Category.DoesNotExist:
            return Response({'status': 'error', 'error': 'Category not found'}, status=404)
from rest_framework.parsers import MultiPartParser, FormParser

class CarPartAPIView(BaseAuthenticatedAPIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        """إضافة قطعة سيارة جديدة (للبائعين فقط)"""
        profile, error = self.get_user_from_token(request)
        if error:
            return error

        if not profile.is_seller():
            return Response({'error': 'Seller privileges required'}, status=403)

        try:
            serializer = CarPartSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(seller=profile)
                return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        except Exception as e:
            return Response({'error': 'Failed to create car part'}, status=400)
    def get(self, request):
            """جلب قطع السيارات مع دعم البحث والتصفية بواسطة البائع أو الفئة"""
            profile, error = self.get_user_from_token(request)
            if error:
                return error

            try:
                query = request.GET.get('query', '')
                category_id = request.GET.get('category')
                seller_id = request.GET.get('seller_id')
                min_price = request.GET.get('min_price')
                max_price = request.GET.get('max_price')
                condition = request.GET.get('condition')
                sort_by = request.GET.get('sort_by', '-created_at')

                car_parts = CarPart.objects.all()

                if query:
                    car_parts = car_parts.filter(Q(name__icontains=query) | Q(description__icontains=query))
                if category_id:
                    car_parts = car_parts.filter(category_id=category_id)
                if seller_id:
                    car_parts = car_parts.filter(seller__id=seller_id)
                if min_price:
                    car_parts = car_parts.filter(price__gte=min_price)
                if max_price:
                    car_parts = car_parts.filter(price__lte=max_price)
                if condition:
                    car_parts = car_parts.filter(condition=condition)

                car_parts = car_parts.order_by(sort_by)
                paginator = Paginator(car_parts, int(request.GET.get('per_page', 10)))
                current_page = paginator.page(int(request.GET.get('page', 1)))

                car_parts_data = []
                for part in current_page:
                    car_parts_data.append({
                        "id": part.id,
                        "name": part.name,
                        "category": part.category.id if part.category else None,
                        "category_name": part.category.name if part.category else "",
                        "description": part.description,
                        "price": str(part.price),
                        "stock": part.stock,
                        "photo": part.photo.url if part.photo else None,
                        "created_at": part.created_at.strftime("%Y-%m-%dT%H:%M:%S"),
                        "seller": {
                            "id": part.seller.id if part.seller else None,
                            "username": part.seller.user.username if part.seller and part.seller.user else None
                        } if part.seller else None
                    })

                return Response({
                    'status': 'success',
                    'results': car_parts_data,
                    'total_pages': paginator.num_pages,
                    'current_page': current_page.number,
                    'total_items': paginator.count
                }, status=200)

            except Exception as e:
                return Response({'error': f'Failed to retrieve car parts: {str(e)}'}, status=400)
    def put(self, request, part_id):
        """تحديث قطعة سيارة (للبائع المالك فقط)"""
        profile, error = self.get_user_from_token(request)
        if error:
            return error

        try:
            car_part = CarPart.objects.get(id=part_id)

            if car_part.seller != profile:
                return Response({'error': 'Not authorized to update this part'}, status=403)

            update_data = {
                'name': request.data.get('name'),
                'description': request.data.get('description'),
                'price': request.data.get('price'),
                'stock': request.data.get('stock'),
                'category': request.data.get('category'),
            }

            update_data = {k: v for k, v in update_data.items() if v is not None}

            if 'photo' in request.FILES:
                update_data['photo'] = request.FILES['photo']

            serializer = CarPartSerializer(car_part, data=update_data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=200)
            return Response(serializer.errors, status=400)

        except CarPart.DoesNotExist:
            return Response({'error': 'Car part not found'}, status=404)
        except Exception as e:
            return Response({'error': f'Failed to update car part: {str(e)}'}, status=400)

class OrderAPIView(BaseAuthenticatedAPIView):
    def post(self, request):
        """إنشاء طلب جديد"""
        profile, error = self.get_user_from_token(request)
        if error:
            return error

        items_data = request.data.get('items')
        if not items_data or not isinstance(items_data, list):
            return Response({'error': 'Invalid or missing items list'}, status=400)

        for item in items_data:
            if 'part_id' not in item or 'quantity' not in item:
                return Response({'error': 'Each item must have a part_id and quantity'}, status=400)

        try:
            with transaction.atomic():
                # ✅ **تحقق من توفر جميع الأجزاء قبل إنشاء الطلب**
                car_parts = {}
                for item_data in items_data:
                    part_id = item_data['part_id']
                    quantity = item_data['quantity']

                    try:
                        car_part = CarPart.objects.get(id=part_id)
                    except CarPart.DoesNotExist:
                        return Response({'error': f'Car part with ID {part_id} not found'}, status=404)

                    if car_part.stock < quantity:
                        return Response({
                            'error': f'Insufficient stock for part {car_part.name}. Available: {car_part.stock}'
                        }, status=400)

                    # حفظ القطع في dict لتجنب جلب نفس العنصر أكثر من مرة
                    car_parts[part_id] = car_part

                # ✅ **الآن، بعد التأكد من أن كل شيء صحيح، أنشئ الطلب**
                order = Order.objects.create(user=profile, status="Pending")

                # ✅ **إنشاء عناصر الطلب وتحديث المخزون**
                for item_data in items_data:
                    part_id = item_data['part_id']
                    quantity = item_data['quantity']
                    car_part = car_parts[part_id]

                    OrderItem.objects.create(
                        order=order,
                        car_part=car_part,
                        quantity=quantity
                    )
                    car_part.stock -= quantity
                    car_part.save()

                serializer = OrderSerializer(order)
                return Response(serializer.data, status=201)

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return Response({'error': f'Failed to create order: {str(e)}'}, status=500)

    def get(self, request):
        """جلب جميع الطلبات للمستخدم الحالي بدون فلترة"""
        profile, error = self.get_user_from_token(request)
        if error:
            return Response({'error': 'Authentication failed'}, status=401)

        try:
            orders = Order.objects.filter(user=profile)

            orders = orders.order_by('-created_at')

            try:
                page = int(request.GET.get('page', 1))
                per_page = int(request.GET.get('per_page', 10))
            except ValueError:
                return Response({'error': 'Invalid pagination parameters'}, status=400)

            paginator = Paginator(orders, per_page)
            try:
                current_page = paginator.page(page)
            except (PageNotAnInteger, EmptyPage):
                return Response({'error': 'Invalid page number'}, status=400)

            # تسلسل النتائج
            serializer = OrderSerializer(current_page, many=True)

            return Response({
                'results': serializer.data,
                'total_pages': paginator.num_pages,
                'current_page': page,
                'total_items': paginator.count
            }, status=200)

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return Response({'error': f'Failed to retrieve orders: {str(e)}'}, status=500)

    def put(self, request, order_id):
        """تحديث حالة الطلب (للبائع أو المشتري)"""
        profile, error = self.get_user_from_token(request)
        if error:
            return error

        try:
            order = Order.objects.get(id=order_id)

            if profile.is_buyer() and order.buyer != profile:
                return Response({'error': 'Not authorized to update this order'}, status=403)
            elif profile.is_seller() and not order.items.filter(car_part__seller=profile).exists():
                return Response({'error': 'Not authorized to update this order'}, status=403)

            new_status = request.data.get('status')
            if not new_status:
                return Response({'error': 'Status is required'}, status=400)

            valid_transitions = {
                'pending': ['confirmed', 'cancelled'],
                'confirmed': ['shipped', 'cancelled'],
                'shipped': ['delivered', 'returned'],
                'delivered': ['completed', 'returned'],
                'returned': ['completed'],
                'completed': [],
                'cancelled': []
            }

            if new_status not in valid_transitions.get(order.status, []):
                return Response({
                    'error': f'Invalid status transition from {order.status} to {new_status}'
                }, status=400)

            order.status = new_status
            order.save()

            serializer = OrderSerializer(order)
            return Response(serializer.data, status=200)

        except Order.DoesNotExist:
            return Response({'error': 'Order not found'}, status=404)
        except Exception as e:
            return Response({'error': 'Failed to update order'}, status=400)


class SellerAccountsAPIView(BaseAuthenticatedAPIView):
    def get(self, request):
        """جلب حسابات البائعين مع دعم التصفح (Pagination)"""
        profile, error = self.get_user_from_token(request)
        if error:
            return error

        try:
            sellers = UserProfile.objects.filter(role='seller').select_related('user').values(
                "id",
                "user__username",
                "user__email",
                "phone"
            )

            page = request.GET.get('page', 1)
            per_page = request.GET.get('per_page', 10)

            try:
                page = int(page)
                per_page = int(per_page)
            except ValueError:
                return Response({'error': 'Invalid page or per_page value'}, status=400)

            paginator = Paginator(sellers, per_page)

            try:
                sellers_page = paginator.page(page)
            except EmptyPage:
                return Response({'error': 'Page not found'}, status=404)

            return Response({
                'sellers': list(sellers_page),
                'total_pages': paginator.num_pages,
                'current_page': page
            }, status=200)

        except Exception as e:
            return Response({'error': f'Failed to retrieve sellers: {str(e)}'}, status=400)

class VerifyPasswordView(BaseAuthenticatedAPIView):
    def post(self, request):
        """التحقق من كلمة المرور فقط"""
        profile, error = self.get_user_from_token(request)
        if error:
            return error

        try:
            password = request.data.get('password')
            if not password:
                return Response({'error': 'Password is required'}, status=400)

            user = profile.user
            if user.check_password(password):
                return Response({'message': 'Password is correct'}, status=200)
            else:
                return Response({'error': 'Incorrect password'}, status=401)

        except Exception as e:
            return Response({'error': f'Password verification failed: {str(e)}'}, status=400)

class SellerSoldOrdersAPIView(BaseAuthenticatedAPIView):
    def get(self, request):
        """إرجاع جميع الطلبات التي تحتوي فقط على المنتجات المباعة الخاصة بالبائع مع حساب السعر الإجمالي بشكل صحيح"""
        profile, error = self.get_user_from_token(request)
        if error:
            return error

        if not profile.is_seller():
            return Response({'error': 'Seller privileges required'}, status=403)

        try:
            orders = Order.objects.filter(items__car_part__seller=profile).distinct()
            orders = orders.order_by('-created_at')

            try:
                page = int(request.GET.get('page', 1))
                per_page = int(request.GET.get('per_page', 10))
            except ValueError:
                return Response({'error': 'Invalid pagination parameters'}, status=400)

            paginator = Paginator(orders, per_page)
            try:
                current_page = paginator.page(page)
            except (PageNotAnInteger, EmptyPage):
                return Response({'error': 'Invalid page number'}, status=400)

            serialized_orders = []
            for order in current_page:
                filtered_items = order.items.filter(car_part__seller=profile)

                total_price = sum(item.quantity * item.total_price for item in filtered_items)

                serialized_order = OrderSerializer(order).data
                serialized_order['items'] = OrderItemSerializer(filtered_items, many=True).data
                serialized_order['total_price'] = total_price

                serialized_orders.append(serialized_order)

            return Response({
                'status': 'success',
                'orders': serialized_orders,
                'total_pages': paginator.num_pages,
                'current_page': current_page.number,
                'total_items': paginator.count
            }, status=200)

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return Response({'error': f'Failed to retrieve seller orders: {str(e)}'}, status=500)
