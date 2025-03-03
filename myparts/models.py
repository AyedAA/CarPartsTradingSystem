from django.db import models
from django.contrib.auth import get_user_model
import pyotp

UserAuth = get_user_model()

class Category(models.Model):
    name = models.CharField(max_length=100)
    photo = models.ImageField(upload_to='category_photos/', default='default.jpg')

    def __str__(self):
        return self.name


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('buyer', 'Buyer'),
        ('seller', 'Seller'),
    ]
    user = models.OneToOneField(UserAuth, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='buyer')
    phone = models.CharField(max_length=9, unique=True)
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    verification_code = models.IntegerField(blank=True, null=True)
    verification_code_created_at = models.DateTimeField(blank=True, null=True)
    is_2fa_enabled = models.BooleanField(default=False)

    def generate_totp_secret(self):
        """توليد مفتاح TOTP جديد للمستخدم."""
        self.totp_secret = pyotp.random_base32()
        self.save()

    def get_totp_uri(self):
        """توليد رابط TOTP لإعداد رمز QR."""
        if not self.totp_secret:
            self.generate_totp_secret()
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.user.email,
            issuer_name="YourAppName"
        )

    def is_seller(self):
        """التحقق مما إذا كان المستخدم بائعًا."""
        return self.role == 'seller'

    def is_buyer(self):
        """التحقق مما إذا كان المستخدم مشتريًا."""
        return self.role == 'buyer'

    def __str__(self):
        return f"{self.user.username} ({self.role})"


class CarPart(models.Model):
    name = models.CharField(max_length=100)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField()
    photo = models.ImageField(upload_to='carparts_photos/')
    created_at = models.DateTimeField(auto_now_add=True)
    seller = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name="products")

    def save(self, *args, **kwargs):
        """ضمان أن المستخدم الذي يضيف المنتج هو بائع."""
        if not self.seller.is_seller():
            raise ValueError("فقط البائعون يمكنهم إضافة قطع الغيار!")
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Order(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name="orders")
    status = models.CharField(max_length=15)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def total_price(self):
        """حساب إجمالي سعر الطلبية."""
        return sum(item.total_price for item in self.items.all())

    def __str__(self):
        return f"Order #{self.id} by {self.user.user.username}"


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")
    car_part = models.ForeignKey(CarPart, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    @property
    def total_price(self):
        """حساب إجمالي سعر القطعة داخل الطلبية."""
        return self.car_part.price * self.quantity

    def __str__(self):
        return f"{self.quantity} x {self.car_part.name} (Order #{self.order.id})"
