from django.db import models

class UserRole(models.TextChoices):
    ADMIN = "Admin", "Admin"
    USER = "User", "User"


class ComponentTypes(models.TextChoices):
    TEXT = "Text", "Text"
    NUMBERIC = "Numeric", "Numeric"
    LIST = "List", "List"


class ListNameChoices(models.TextChoices):
    RAMMER = "RAMMER", "Type of rammer used"
    MOLD = "MOLD", "Size of mold"
    EQUIPMENT = "EQUIPMENT", "Equipment"
    LIMIT_TESTS = "LIMIT_TESTS" , "Limit Tests"
    METHOD = "METHOD", "Method"
    PROCEDURE = "PROCEDURE", "Procedure used"
    DISPERSON_AGENT = "DISPERSON_AGENT", "Disperson agent"
    SAMPLE_PREPARATION = "SAMPLE_PREPARATION", "Sample Preparation"
    TEST_METHOD = "TEST_METHOD", "Test Method"



class ActionType(models.TextChoices):
    CALIBRATION = 'Calibration', 'Calibration'
    PREVENTION = 'Prevention', 'Prevention'

class ListType(models.TextChoices):
    ANALYSESLIST ='analyses_list', 'Analyses List'
    SAMPLEFORMFIELD = 'sample_form_field', 'Sample Form Field',
    COMPONENT = 'component', 'Component',
    REQUESTFORMFIELD = 'request_form_field', 'Request Form Field',
    MAILLIST = 'mail_list', 'Mail List',
    