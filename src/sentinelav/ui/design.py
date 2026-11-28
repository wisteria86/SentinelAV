# Purpose: Compose the reference-design page mixins and re-export shared widgets.
# Works with: ui.core.design_components, ui.core.design_dashboard, ui.core.design_reports, ui.core.design_scan, ui.core.design_settings
# Used by: entrypoint, ui.application, ui.core.lab_ui, ui.core.protection

from .core.design_components import (
    InactiveSwitch,
    PathLabel,
    configure_app,
    pixmap,
    icon,
    art,
    STYLE,
    PATHS,
)
from .core.design_shell import DesignShellMixin
from .core.design_dashboard import DashboardMixin
from .core.design_scan import ScanPageMixin
from .core.design_reports import ReportsPageMixin
from .core.design_settings import SettingsPageMixin


class DesignMixin(
    DesignShellMixin, DashboardMixin, ScanPageMixin, ReportsPageMixin, SettingsPageMixin
):
    """Bundles the visual building blocks of the window: page shell, dashboard, scan page, reports page
    and settings page.
    """

    pass
