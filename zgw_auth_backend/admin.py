from django.contrib import admin

from .models import ApplicationCredentials


@admin.register(ApplicationCredentials)
class ApplicationCredentialsAdmin(admin.ModelAdmin):
    list_display = ("client_id",)
    search_fields = ("clien_id",)
