# Purpose: Shared inspection policy validation across all scanner entry points.
# Works with: sibling modules in platform
# Used by: detection.engine, monitoring.monitor_loop, platform.windows_service, tests.unit.test_runtime_guards

"""Shared inspection policy validation across all scanner entry points."""

# Generalized detection is on by default. neural_gray runs MalConv only on undecided PE files; emulation stays opt-in.
DEFAULTS = dict(
    archives=True,
    amsi=False,
    advanced=True,
    emulation=False,
    content=True,
    documents=True,
    model=True,
    reputation=False,
    signature_free=False,
    neural=False,
    neural_gray=True,
    clamav=True,
    rule_packs=True,
    md5_feed=True,
    score_all=False,
    capa=True,
    capa_memory=False,
)


def inspection_options(value=None):
    """Validate the scan options and fill in defaults for anything not set.

    Unknown keys or wrong value types raise ValueError. Some options switch others on (any learned
    model or emulation needs the advanced pipeline), and signature-free mode switches off every
    signature-based layer.
    """
    value = {} if value is None else value
    if not isinstance(value, dict) or set(value) - set(DEFAULTS) - {
        'analysis_store',
        'analysis_trust',
        'emulation_backend',
        'emulation_profile',
    }:
        raise ValueError('Unknown inspection policy fields')
    result = dict(DEFAULTS)
    for key, setting in value.items():
        if key in ('emulation_backend', 'emulation_profile'):
            choices = (
                ('speakeasy', 'minimal')
                if key == 'emulation_backend'
                else ('background', 'deep', 'lab')
            )
            if setting not in choices:
                raise ValueError('Invalid emulator selection')
            result[key] = setting
            continue
        if key in ('analysis_store', 'analysis_trust'):
            from pathlib import Path

            if (
                not isinstance(setting, str)
                or len(setting) > 32768
                or not Path(setting).is_absolute()
            ):
                raise ValueError('Invalid analysis store')
            result[key] = setting
            continue
        if type(setting) is not bool:
            raise ValueError('Inspection policy settings must be booleans')
        result[key] = setting
    if result['emulation'] or result['model'] or result['reputation'] or result['neural']:
        result['advanced'] = True
    if result['signature_free']:
        result['clamav'] = False
        result['rule_packs'] = False
        result['md5_feed'] = False
        if result['amsi'] or result['reputation']:
            raise ValueError('Signature-free inspection forbids AMSI and reputation feeds')
        result['advanced'] = True
    return result
