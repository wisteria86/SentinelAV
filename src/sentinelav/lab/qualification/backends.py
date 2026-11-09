# Purpose: Expose the stable backend API; delegate implementation to backend modules.
# Works with: lab.qualification.backend_control, lab.qualification.backend_hyperv,
#   lab.qualification.backend_recovery, lab.qualification.backend_sandbox
# Used by: lab.qualification.evaluation_environment, lab.qualification.guest_inventory,
#   lab.qualification.guest_telemetry, lab.qualification.runner

"""Public guest-backend API; implementations are grouped by lifecycle role."""
from .backend_control import Blocked,run,powershell,quote,read_export
from .backend_sandbox import Sandbox,shutil_copy
from .backend_hyperv import HyperV
from .backend_recovery import reconcile
