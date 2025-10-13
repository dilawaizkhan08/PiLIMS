# project/asgi.py
import os
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project.settings")

# plain Django ASGI app handles normal views + /events/
application = get_asgi_application()
