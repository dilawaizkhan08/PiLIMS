from app.signals import set_current_user

class TrackUserMixin:
    """Automatically sets the current user for signals in any DRF view."""
    def initialize_request(self, request, *args, **kwargs):
        drf_request = super().initialize_request(request, *args, **kwargs)
        # ✅ DRF authentication has not yet run here — so we delay the set
        return drf_request

    def initial(self, request, *args, **kwargs):
        # ✅ DRF authentication has finished here, so request.user is the actual token user
        if request.user and request.user.is_authenticated:
            set_current_user(request.user)
        return super().initial(request, *args, **kwargs)
