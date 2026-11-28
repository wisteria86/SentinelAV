# Purpose: Load large third-party YARA rule packs (YARA-Forge) from the definitions area and classify their matches.
# Works with: detection.definition_paths, detection.engine, detection.threat_score
# Used by: detection.engine, updates.definition_feeds, tools.evaluation.evaluate_false_positives

"""Load large third-party YARA rule packs and classify their matches.

A pack is one rule file plus `pack.json`, which pins its SHA-256, source and
the rules disabled after false-positive review. Packs are compiled once and the
compiled form is cached beside them, keyed by the source digest.

Family and exploit rules with a score of 70 or more are decisive. Rules that
describe techniques (SUSP, INDICATOR, HKTL, PUA, GEN and similar) only add capped
weight, so a single broad rule cannot convict a file.
"""
import hashlib
import json
from sentinelav.detection.definition_paths import definitions_dir

PACKS = ('yara-forge',)
DECISIVE_SCORE = 70
TECHNIQUE_TOKENS = {'SUSP', 'SUSPICIOUS', 'INDICATOR', 'HKTL', 'PUA', 'HUNT', 'HUNTING', 'GEN', 'GENERIC', 'TOOL',
    'LOLBIN', 'LOLBAS', 'ANOMALY', 'OBFUSC', 'CAPABILITY', 'CAPABILITIES', 'SIGNED', 'PE', 'METHODOLOGY', 'INFO'}
EXTERNALS = dict(filename='', filepath='', extension='', filetype='', owner='')
MATCH_TIMEOUT = 10


class PackError(ValueError):
    """Raised when a rule pack is missing or does not match its pinned digest."""
    pass


def _tokens(name):
    """Split a rule name into its upper-case, underscore-separated words."""
    return set(name.upper().split('_'))


def classify(identifier, meta, disabled=()):
    """Return the evidence a match contributes: decisive, technique, or nothing."""
    if identifier in disabled:
        return None
    score = meta.get('score', 70)
    score = score if isinstance(score, int) else 70
    description = str(meta.get('description') or identifier)[:200]
    author = str(meta.get('author') or '')[:60]
    if _tokens(identifier) & TECHNIQUE_TOKENS or score < DECISIVE_SCORE:
        weight = max(15, min(35, score - 45))
        return dict(kind='technique', rule=identifier, code='pack_' + identifier[:60], scope='generic',
            layer='generic_yara', group='yara_pack', weight=weight, category=_category(identifier),
            description=f'Third-party rule {identifier}: {description}' + (f' ({author})' if author else ''))
    return dict(kind='family', rule=identifier, description=description, author=author, score=score)


def _category(identifier):
    """Guess a threat category (Ransomware, Stealer, ...) from words in the rule name, defaulting to
    'Technique'.
    """
    for token in identifier.upper().split('_'):
        if token in ('RANSOM', 'RANSOMWARE', 'STEALER', 'LOADER', 'DROPPER', 'BACKDOOR', 'RAT', 'MINER', 'WEBSHELL', 'EXPL', 'EXPLOIT'):
            return token.capitalize()
    return 'Technique'


class RulePack:
    """One installed third-party YARA rule pack, compiled and ready to match."""
    def __init__(self, name, folder=None):
        """Load the pack: verify the rule file against its pinned SHA-256, then use the cached compiled
        rules if they are still valid, or compile and cache them.
        """
        import yara
        self.name = name
        self.folder = folder or definitions_dir(name)
        manifest_path = self.folder / 'pack.json'
        if not manifest_path.is_file():
            raise PackError(f'Rule pack {name} is not installed')
        self.manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        source = self.folder / self.manifest['file']
        raw = source.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != self.manifest['sha256']:
            raise PackError(f'Rule pack {name} does not match its pinned digest')
        self.disabled = set(self.manifest.get('disabled', {}))
        compiled = self.folder / f'compiled-{digest[:16]}.yarc'
        self.rules = None
        if compiled.is_file() and self.manifest.get('compiled_sha256') == hashlib.sha256(compiled.read_bytes()).hexdigest():
            try:
                self.rules = yara.load(str(compiled))
            except yara.Error:
                self.rules = None
        if self.rules is None:
            self.rules = yara.compile(source=raw.decode('utf-8'), externals=EXTERNALS, includes=False)
            self.rules.save(str(compiled))
            self.manifest['compiled_sha256'] = hashlib.sha256(compiled.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(self.manifest, indent=2), encoding='utf-8')
        self.count = sum(1 for _ in self.rules)

    def match(self, data):
        """Classified evidence for every enabled rule that matches these bytes."""
        found = []
        for match in self.rules.match(data=bytes(data), timeout=MATCH_TIMEOUT, externals=EXTERNALS):
            item = classify(match.rule, match.meta, self.disabled)
            if item:
                found.append(item)
        return found

    def summary(self):
        """Return a short description of the pack (name, release, rule count, disabled count, digest)
        for the UI.
        """
        return dict(name=self.name, release=self.manifest.get('release'), rules=self.count,
            disabled=len(self.disabled), sha256=self.manifest['sha256'])


def load_packs():
    """Installed packs and one warning per pack that could not load."""
    packs, warnings = [], []
    for name in PACKS:
        # A pack that was never installed is a status for the Updates page, not a warning on every scan.
        if not (definitions_dir(name) / 'pack.json').is_file():
            continue
        try:
            packs.append(RulePack(name))
        except PackError as error:
            warnings.append(str(error))
        except Exception as error:
            warnings.append(f'Rule pack {name} unavailable: {str(error)[:160]}')
    return packs, warnings


def install(name, source_path, release, url, upstream_sha256, disabled=None):
    """Pin a downloaded rule file as the current pack."""
    folder = definitions_dir(name)
    raw = source_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    target = folder / f'rules-{digest[:16]}.yar'
    target.write_bytes(raw)
    previous = {}
    if (folder / 'pack.json').is_file():
        previous = json.loads((folder / 'pack.json').read_text(encoding='utf-8')).get('disabled', {})
    manifest = dict(file=target.name, sha256=digest, release=release, url=url, upstream_sha256=upstream_sha256,
        disabled=disabled if disabled is not None else previous)
    (folder / 'pack.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest
