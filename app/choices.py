from django.db import models

class UserRole(models.TextChoices):
    ADMIN = "Admin", "Admin"
    USER = "User", "User"


class ComponentTypes(models.TextChoices):
    TEXT = "Text", "Text"
    NUMBERIC = "Numeric", "Numeric"
    LIST = "List", "List"


class ActionType(models.TextChoices):
    CALIBRATION = 'Calibration', 'Calibration'
    PREVENTION = 'Prevention', 'Prevention'

class ListType(models.TextChoices):
    ANALYSESLIST ='analyses_list', 'Analyses List'
    SAMPLEFORMFIELD = 'sample_form_field', 'Sample Form Field',
    COMPONENT = 'component', 'Component',
    REQUESTFORMFIELD = 'request_form_field', 'Request Form Field',
    MAILLIST = 'mail_list', 'Mail List',
    

class RoundingChoices(models.IntegerChoices):
    HALF_UP = 1, "Decimal Places W/0.5 Up"
    HALF_ODD_UP = 2, "Decimal Places W/0.5 Odd Up"

