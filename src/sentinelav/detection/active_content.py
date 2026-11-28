# Purpose: RTF object and HTML inline-script extraction without browser/COM execution.
# Works with: sibling modules in detection
# Used by: detection.advanced_pipeline, tests.unit.test_advanced_evaluation, tests.unit.test_integrated_analysis

"""RTF object and HTML inline-script extraction without browser/COM execution."""

from html.parser import HTMLParser
import re


class InlineScripts(HTMLParser):
    """HTML parser that collects inline <script> bodies and on... event-handler attributes as text.

    Nothing is executed and external scripts are never downloaded. Strict size budgets stop a huge
    or hostile page from using too much memory; going over a budget raises ValueError.
    """

    def __init__(self):
        """Start with an empty collection and no script currently open."""
        super().__init__(convert_charrefs=False)
        self.active = False
        self.parts = []
        self.sources = []
        self.bytes = 0
        self.omissions = []

    def handle_starttag(self, tag, attributes):
        """Note when a <script> opens, and collect any inline event handlers (onclick, onload, ...) on
        any tag.
        """
        attributes = dict(attributes)
        if tag.casefold() == 'script':
            if self.active:
                self.omissions.append('Nested script markup omitted')
            self.active = True
            self.parts = []
            if attributes.get('src'):
                self.omissions.append('External script was not fetched')
        for key, value in attributes.items():
            if key.casefold().startswith('on') and value:
                self.add('html-event-handler', value)

    def handle_endtag(self, tag):
        """When a <script> closes, save the text gathered inside it."""
        if tag.casefold() == 'script' and self.active:
            self.add('html-inline-script', ''.join(self.parts))
            self.active = False
            self.parts = []

    def handle_data(self, value):
        """Gather text while we are inside a <script> tag."""
        if self.active:
            if sum(len(p) for p in self.parts) + len(value) > 256 * 1024:
                raise ValueError('Inline script size cap')
            self.parts.append(value)

    def add(self, label, value):
        """Store one extracted script as (label, bytes), enforcing the count and size budgets."""
        payload = value.encode('utf-8', errors='replace')
        if (
            len(self.sources) >= 32
            or len(payload) > 256 * 1024
            or self.bytes + len(payload) > 2 * 1024 * 1024
        ):
            raise ValueError('HTML active-content budget')
        self.bytes += len(payload)
        self.sources.append((label + '-' + str(len(self.sources)), payload))


def active_sources(data, suffix):
    """Pull embedded active content out of RTF and HTML documents so it can be scanned.

    For RTF that means the hex-encoded embedded objects (often used to smuggle in executables); for
    HTML it means inline scripts and event handlers. Other file types are ignored.

    Returns (sources, omissions): sources is a list of (label, bytes) pairs, and omissions lists
    anything we skipped or could not fully inspect.
    """
    is_rtf = data[:16].lstrip().startswith(b'{\\rtf')
    is_html = suffix in ('.html', '.htm', '.hta', '.xhtml') or data[
        :256
    ].lstrip().lower().startswith((b'<!doctype html', b'<html'))
    if not (is_rtf or is_html):
        return [], []
    if len(data) > 8 * 1024 * 1024:
        return [], ['Active-document input size cap']
    sources = []
    omissions = []
    if is_rtf:
        total = 0
        # Embedded RTF objects are stored as long runs of hex digits after the \objdata keyword.
        for index, match in enumerate(
            re.finditer(rb'\\objdata\s+([0-9a-fA-F\s]{16,8388608})', data)
        ):
            if index >= 16:
                omissions.append('RTF object count cap')
                break
            compact = re.sub(rb'\s', b'', match[1])
            if len(compact) % 2:
                omissions.append('Odd-length RTF object data')
                continue
            payload = bytes.fromhex(compact.decode('ascii'))
            total += len(payload)
            if len(payload) > 4 * 1024 * 1024 or total > 8 * 1024 * 1024:
                omissions.append('RTF object byte budget')
                break
            sources.append(('rtf-object-' + str(index), payload))
        omissions.append('RTF partial extraction: no OLE activation or general RTF rendering')
    if is_html:
        parser = InlineScripts()
        try:
            parser.feed(data.decode('utf-8-sig', errors='replace'))
            parser.close()
            if parser.active:
                parser.omissions.append('Unterminated inline script')
        except (ValueError, RecursionError) as error:
            parser.omissions.append(str(error))
        sources.extend(parser.sources)
        omissions.extend(parser.omissions)
        omissions.append('HTML scripts inspected as text; no DOM or JavaScript runtime')
    return sources, omissions
