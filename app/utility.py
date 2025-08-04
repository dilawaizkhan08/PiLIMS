
from django.core.mail import send_mail
from project import settings
from rest_framework.response import Response
from rest_framework import status
from smtplib import SMTPException
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import logging
logger = logging.getLogger(__name__)
scheduler = BackgroundScheduler()
scheduler.start()


# paginate queryset generic function
def paginate_queryset(request, view, queryset, serializer_class):
    page = view.paginate_queryset(queryset)
    if page is not None:
        serializer = serializer_class(page, many=True, context={"request": request})
        return view.get_paginated_response(serializer.data)
    serializer = serializer_class(queryset, many=True, context={"request": request})
    return Response(serializer.data)

# send_mail generic function
def send_email(subject, message, recipient_list):
    def background_send_email():
        try:
            send_mail(
                subject,
                message,
                settings.EMAIL_HOST_USER,
                recipient_list,
                fail_silently=False
            )
        except SMTPException as e:
            logger.error(f"SMTPException: Failed to send email to {recipient_list}: {e}") # we have not set up logging settings so it will log only on console
        except Exception as e:
            logger.error(f"Unexpected error while sending email to {recipient_list}: {e}")
    scheduler.add_job(background_send_email)
