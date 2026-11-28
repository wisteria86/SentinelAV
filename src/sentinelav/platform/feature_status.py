# Purpose: Read-only capability descriptions; dependency presence is not efficacy.
# Works with: platform.emulation_support
# Used by: ui.defense_settings

"""Read-only capability descriptions; dependency presence is not efficacy."""
import importlib.util
import os


def feature_status(options=None):
    """Describe which optional analysis features have their dependencies installed, for the settings
    page. Presence does not mean they work well.
    """
    options=options or {}
    rows=[]
    for name,package,key in [('CPU / Win32 emulation','unicorn','emulation'),('VBA extraction','oletools','documents')]:
        try: available=importlib.util.find_spec(package) is not None
        except (ImportError,ValueError,ModuleNotFoundError): available=False
        rows.append(dict(feature=name,enabled=bool(options.get(key,False)),
            state='Dependency present; execution unverified' if available else 'Dependency missing',dependency=package))
        if package=='unicorn' and available:
            try:
                import unicorn
                from sentinelav.platform.emulation_support import compatibility
                support=compatibility(unicorn.__version__)
                if not support['available']: rows[-1]['state']=support['reason']
            except (ImportError,OSError) as error: rows[-1]['state']='Dependency unavailable: '+str(error)
    for key in ('model','reputation'):
        rows.append(dict(feature=key.capitalize(),enabled=bool(options.get(key,False)),
            state='Requires a signed, unexpired artifact and reviewed publisher pin'))
    rows.append(dict(feature='Native telemetry',state='Protected collector and Windows ETW authorization required',platform=os.name))
    return rows
