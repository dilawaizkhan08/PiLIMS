import shutil
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from app.utility import (
    import_component_summary,
    import_pouch_report,
)


class Command(BaseCommand):
    help = "Import instrument reports"

    def add_arguments(self, parser):
        parser.add_argument(
            "--file",
            type=str,
            help="Specific report file",
        )

    def handle(self, *args, **options):

        custom_file = options.get("file")

        # -----------------------------------
        # Import specific file
        # -----------------------------------
        if custom_file:

            file_path = Path(custom_file)

            if not file_path.exists():
                self.stdout.write(
                    self.style.ERROR(f"File not found: {file_path}")
                )
                return

            self.process_file(file_path)
            return

        # -----------------------------------
        # Default instrument folder
        # -----------------------------------
        reports_dir = (
            Path(settings.BASE_DIR)
            / "media"
            / "instrument"
        )

        if not reports_dir.exists():
            self.stdout.write(
                self.style.ERROR(
                    f"Directory not found: {reports_dir}"
                )
            )
            return

        # Process Blend Report
        blend_file = reports_dir / "BLEND REPORT.txt"

        if blend_file.exists():
            self.process_file(blend_file)
        else:
            self.stdout.write(
                self.style.WARNING(
                    "BLEND REPORT.txt not found."
                )
            )

        # Process all pouch csv files
        csv_files = sorted(reports_dir.glob("*.csv"))

        if not csv_files:
            self.stdout.write(
                self.style.WARNING(
                    "No pouch csv files found."
                )
            )

        for csv_file in csv_files:
            self.process_file(csv_file)

    def process_file(self, file_path: Path):

        self.stdout.write(f"\nReading: {file_path}")

        try:

            suffix = file_path.suffix.lower()

            if suffix == ".txt":

                import_component_summary(str(file_path))

            elif suffix == ".csv":

                import_pouch_report(str(file_path))

            else:

                self.stdout.write(
                    self.style.WARNING(
                        f"Unsupported file: {file_path.name}"
                    )
                )
                return

            self.stdout.write(
                self.style.SUCCESS(
                    f"{file_path.name} imported successfully."
                )
            )

            # Move file only after successful import
            self.move_to_processed(file_path)

        except Exception as e:

            self.stdout.write(
                self.style.ERROR(
                    f"{file_path.name}: {e}"
                )
            )

    def move_to_processed(self, file_path: Path):
        """
        Move processed file to media/processed_instrument
        """

        processed_dir = (
            Path(settings.BASE_DIR)
            / "media"
            / "processed_instrument"
        )

        processed_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        destination = processed_dir / file_path.name

        # Prevent overwrite
        if destination.exists():

            stem = file_path.stem
            suffix = file_path.suffix

            counter = 1

            while True:

                new_destination = (
                    processed_dir /
                    f"{stem}_{counter}{suffix}"
                )

                if not new_destination.exists():
                    destination = new_destination
                    break

                counter += 1

        shutil.move(
            str(file_path),
            str(destination),
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Moved to: {destination}"
            )
        )