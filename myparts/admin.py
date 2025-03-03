from django.contrib import admin
from .models import Category, CarPart,UserProfile
from django_otp.plugins.otp_totp.models import TOTPDevice

admin.site.register(Category)
admin.site.register(CarPart)
admin.site.unregister(TOTPDevice)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'phone', 'totp_secret_display')
    list_filter = ('role',)
    search_fields = ('user__username', 'user__email', 'phone')

    def totp_secret_display(self, obj):
        """إخفاء مفتاح TOTP لأغراض الأمان"""
        return "Hidden for security" if obj.totp_secret else "Not set"
    totp_secret_display.short_description = "TOTP Secret"

