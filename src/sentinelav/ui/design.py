# Purpose: Compose the reference-design page mixins and re-export shared widgets.
# Works with: ui.design_components, ui.design_dashboard, ui.design_reports, ui.design_scan, ui.design_settings
# Used by: entrypoint, ui.application, ui.lab_ui, ui.protection

from .design_components import InactiveSwitch,PathLabel,configure_app,pixmap,icon,art,STYLE,PATHS
from .design_shell import DesignShellMixin
from .design_dashboard import DashboardMixin
from .design_scan import ScanPageMixin
from .design_reports import ReportsPageMixin
from .design_settings import SettingsPageMixin

class DesignMixin(DesignShellMixin, DashboardMixin, ScanPageMixin, ReportsPageMixin, SettingsPageMixin):
    """Bundles the visual building blocks of the window: page shell, dashboard, scan page, reports page
    and settings page.
    """
    pass
