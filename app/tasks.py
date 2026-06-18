import os
import shutil
from celery import shared_task
from app.utility import parse_blend_report
from django.conf import settings

WATCH_FOLDER = os.path.join(settings.BASE_DIR, "blend_report_in")
PROCESSED_FOLDER = os.path.join(settings.BASE_DIR, "blend_report_processed")

os.makedirs(WATCH_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)


@shared_task
def process_blend_reports():
    print("🔥 TASK STARTED")

    BASE_DIR = settings.BASE_DIR

    WATCH_FOLDER = os.path.join(BASE_DIR, "blend_report_in")
    PROCESSED_FOLDER = os.path.join(BASE_DIR, "blend_report_processed")

    os.makedirs(WATCH_FOLDER, exist_ok=True)
    os.makedirs(PROCESSED_FOLDER, exist_ok=True)

    for file_name in os.listdir(WATCH_FOLDER):

        if not file_name.endswith(".txt"):
            continue

        file_path = os.path.join(WATCH_FOLDER, file_name)

        try:
            parse_blend_report(file_path)

            shutil.move(
                file_path,
                os.path.join(PROCESSED_FOLDER, file_name)
            )

        except Exception as e:
            print("Error:", e)


