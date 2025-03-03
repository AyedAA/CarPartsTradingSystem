from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Category, UserProfile, CarPart, Order, OrderItem

User = get_user_model()

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            raise serializers.ValidationError("Both username and password are required.")

        return data
    
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        
class UserProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ('id', 'username', 'email', 'role', 'phone')

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ('id', 'name', 'photo')
        
class CarPartSerializer(serializers.ModelSerializer):
    seller_name = serializers.CharField(source='seller.user.username', read_only=True)
    seller_id = serializers.IntegerField(source='seller.id', read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    category_id = serializers.IntegerField(source='category.id', read_only=True)
    photo = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = CarPart
        fields = ('id', 'name', 'category', 'category_id', 'category_name', 
                 'description', 'price', 'stock', 'photo', 'created_at', 
                 'seller', 'seller_id', 'seller_name')
        read_only_fields = ('seller', 'created_at')

    def validate_price(self, value):
        if value is not None and value < 0:
            raise serializers.ValidationError("Price cannot be negative")
        return value

    def validate_stock(self, value):
        if value is not None and value < 0:
            raise serializers.ValidationError("Stock cannot be negative")
        return value
    
class OrderItemSerializer(serializers.ModelSerializer):
    car_part_name = serializers.CharField(source='car_part.name', read_only=True)
    total_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    photo = serializers.ImageField(source='car_part.photo', read_only=True)

    class Meta:
        model = OrderItem
        fields = ('id', 'car_part', 'car_part_name', 'photo', 'quantity', 'total_price')

class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    user_name = serializers.CharField(source='user.user.username', read_only=True)
    total_price = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    
    class Meta:
        model = Order
        fields = ('id', 'user', 'user_name', 'items', 'total_price', 'created_at')
        read_only_fields = ('user', 'created_at')