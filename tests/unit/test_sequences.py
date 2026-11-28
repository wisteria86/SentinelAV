# Purpose: Verify test sequences behavior using controlled fixtures.
# Works with: monitoring.sequences
# Used by: tests.unit.test_monitoring

import unittest
from xml.sax.saxutils import escape
from sentinelav.monitoring.sequences import SequenceDetector, parse_event

GUID = '{12345678-1234-5678-1234-567812345678}'


def event(record, kind, guid=GUID, second=None):
    fields = dict(
        ProcessGuid=guid,
        ProcessId='42',
        Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        UtcTime=f'2026-11-03 10:00:{second if second is not None else record:02d}.000',
        CommandLine='powershell.exe -EncodedCommand INERT_NOT_EXECUTED',
        TargetObject='HKU\\example\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Demo',
        Initiated='true',
        DestinationIp='8.8.8.8',
    )
    return dict(id=kind, record=record, fields=fields)


def xml_event(value):
    fields = ''.join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in value['fields'].items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Sysmon"/>'
        f'<EventID>{value["id"]}</EventID><EventRecordID>{value["record"]}</EventRecordID>'
        f'</System><EventData>{fields}</EventData></Event>'
    )


class SequenceTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.now = 100
        self.detector = SequenceDetector(self.events.append, clock=lambda: self.now)

    def test_ordered_same_identity_emits_one_review_alert(self):
        for record, kind in ((1, 1), (2, 13), (3, 3), (4, 3)):
            self.detector.consume(parse_event(xml_event(event(record, kind))))
        self.assertEqual(len(self.events), 1)
        self.assertEqual(len(self.events[0]['sequence']), 3)
        self.assertFalse(self.events[0]['automatic_response_eligible'])

    def test_reused_pid_different_guid_does_not_correlate(self):
        self.detector.consume(event(1, 1))
        self.detector.consume(event(2, 13, '{87654321-1234-5678-1234-567812345678}'))
        self.detector.consume(event(3, 3))
        self.assertEqual(self.events, [])

    def test_wrong_order_private_network_and_expired_sequence_do_not_alert(self):
        self.detector.consume(event(1, 1))
        self.detector.consume(event(2, 3))
        self.detector.consume(event(3, 13))
        private = event(4, 3)
        private['fields']['DestinationIp'] = '192.0.2.1'
        self.detector.consume(private)
        self.assertEqual(self.events, [])
        self.now += 121
        self.detector.consume(event(5, 3))
        self.assertEqual(self.events, [])

    def test_duplicates_and_backdated_events_do_not_complete_sequence(self):
        self.detector.consume(event(1, 1, second=10))
        self.detector.consume(event(2, 13, second=9))
        self.detector.consume(event(3, 3, second=11))
        self.assertEqual(self.events, [])
        self.detector.consume(event(2, 13, second=12))
        self.assertEqual(self.events, [])

    def test_xml_bounds_and_provider_are_validated(self):
        for raw in (
            '<broken',
            '<!DOCTYPE x><Event/>',
            'A' * 65537,
            xml_event(event(1, 1)).replace('Microsoft-Windows-Sysmon', 'Other'),
        ):
            with self.assertRaises(ValueError):
                parse_event(raw)

    def test_capacity_is_bounded(self):
        self.detector.capacity = 1
        self.detector.consume(event(1, 1))
        self.detector.consume(event(2, 1, '{87654321-1234-5678-1234-567812345678}'))
        self.assertEqual(len(self.detector.entities), 1)
