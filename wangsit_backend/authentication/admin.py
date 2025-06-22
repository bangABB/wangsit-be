from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User

from .models import UserProfile

# Define an inline admin for UserProfile
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'profile'

# Extend the UserAdmin to include the profile inline
class UserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)
    list_display = ('username', 'email', 'first_name', 'last_name', 'get_asal_sekolah', 'is_staff')
    
    def get_asal_sekolah(self, instance):
        return instance.profile.asal_sekolah
    get_asal_sekolah.short_description = 'Asal Sekolah'

# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

# Register the UserProfile model on its own
admin.site.register(UserProfile)
