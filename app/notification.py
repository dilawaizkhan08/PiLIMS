
from app.models import Notification


# Must match the module value stored in your Permission table.
SAMPLE_MODULE = "app_dynamicformentry"


def create_sample_logged_notification(sample):
    return Notification.objects.create(
        notification_type="sample_logged",
        audience="all",
        title="Sample Logged",
        message=f"Sample {sample.sample_text_id} has been logged.",
        sample=sample,
    )


def create_sample_completed_notification(sample):
    return Notification.objects.create(
        notification_type="sample_completed",
        audience="permission",
        required_module=SAMPLE_MODULE,
        required_action="release",
        title="Sample Completed",
        message=f"Sample {sample.sample_text_id} has been completed.",
        sample=sample,
    )


def create_out_of_specs_notification(
    sample,
    component_name,
    result_value,
):
    return Notification.objects.create(
        notification_type="out_of_specs",
        audience="permission",
        required_module=SAMPLE_MODULE,
        required_action="release",
        title="Results Out of Specs",
        message=(
            f"Sample {sample.sample_text_id}: "
            f"{component_name} result ({result_value}) "
            "is out of specs."
        ),
        sample=sample,
    )





