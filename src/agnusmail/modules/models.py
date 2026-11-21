"""Import every ORM model so ``Base.metadata`` is complete.

Used by Alembic (autogenerate/check) and by tests that build the schema.
"""

from agnusmail.modules.abuse import models as abuse_models
from agnusmail.modules.addresses import models as address_models
from agnusmail.modules.admin import models as admin_models
from agnusmail.modules.attachments import models as attachment_models
from agnusmail.modules.audit import models as audit_models
from agnusmail.modules.devices import models as device_models
from agnusmail.modules.domains import models as domain_models
from agnusmail.modules.folders import models as folder_models
from agnusmail.modules.identity import models as identity_models
from agnusmail.modules.inbound import models as inbound_models
from agnusmail.modules.jobs import models as job_models
from agnusmail.modules.keys import models as key_models
from agnusmail.modules.messages import models as message_models
from agnusmail.modules.outbound import models as outbound_models
from agnusmail.modules.passkeys import models as passkey_models
from agnusmail.modules.portal import models as portal_models
from agnusmail.modules.quotas import models as quota_models
from agnusmail.modules.recovery import models as recovery_models

__all__ = [
    "abuse_models",
    "address_models",
    "admin_models",
    "attachment_models",
    "audit_models",
    "device_models",
    "domain_models",
    "folder_models",
    "identity_models",
    "inbound_models",
    "job_models",
    "key_models",
    "message_models",
    "outbound_models",
    "passkey_models",
    "portal_models",
    "quota_models",
    "recovery_models",
]
