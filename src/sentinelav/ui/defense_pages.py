# Purpose: Build advanced-protection controls and present capability details.
# Works with: platform.windows_service
# Used by: ui.defense_ui

"""Honest layer status, bounded manual inspection, and opt-in response policy."""
import json
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget, QCheckBox, QPlainTextEdit, QMessageBox, QHeaderView, QLineEdit, QScrollArea
from sentinelav.platform.windows_service import read_health


class DefensePagesMixin:
    """Adds the Defense tab to Settings: layer status, inspection options, analysis-data feeds and the
    automatic response policy.
    """
    def settings_page(self):
        """Build the Defense tab and its four sub-tabs (Layers, Inspection, Analysis Data, Response
        Policy).
        """
        super().settings_page()
        outer_tabs=self.stack.widget(5).findChild(QTabWidget)
        wrapper=QWidget(); wrapper_layout=QVBoxLayout(wrapper); wrapper_layout.setContentsMargins(0,0,0,0)
        self.defense_tabs=QTabWidget(); wrapper_layout.addWidget(self.defense_tabs)
        outer_tabs.addTab(wrapper,'Defense')
        tabs=self.defense_tabs
        page=QWidget(); layout=QVBoxLayout(page); layout.setContentsMargins(14,10,14,10)
        self.layer_table=self.table(['Layer','State / scope'])
        self.layer_table.setFixedHeight(175)
        self.layer_table.setStyleSheet('QTableWidget::item {padding:1px;}')
        self.layer_table.horizontalHeader().setFixedHeight(26)
        self.layer_table.verticalHeader().setMinimumSectionSize(20)
        self.layer_table.verticalHeader().setDefaultSectionSize(20)
        self.layer_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.ResizeToContents)
        self.layer_table.cellDoubleClicked.connect(self.show_layer_details)
        layout.addWidget(self.layer_table)
        row=QHBoxLayout(); self.action(row,'Refresh Layer Status',self.refresh_defense_layers); row.addStretch(); layout.addLayout(row)
        tabs.addTab(page,'Layers')
        page=QWidget(); layout=QVBoxLayout(page); layout.setContentsMargins(14,12,14,12)
        options=self.store.get('inspection_options',{})
        self.archive_option=QCheckBox('Inspect files inside archives with bounded expansion')
        self.archive_option.setChecked(options.get('archives',True))
        self.advanced_option=QCheckBox('Analyze file content, structure and behavior traits')
        self.advanced_option.setChecked(options.get('advanced',True))
        self.emulation_option=QCheckBox('Experimental CPU emulation (requires optional Unicorn dependency)')
        self.emulation_option.setChecked(options.get('emulation',False))
        self.emulation_option.setToolTip('Bounded CPU and Win32 subset. Unmodeled APIs stop analysis and report incomplete coverage.')
        layout.addWidget(self.advanced_option)
        layout.addWidget(self.emulation_option)
        self.document_option=QCheckBox('Extract Office macros and document active content')
        self.document_option.setChecked(options.get('documents',True)); layout.addWidget(self.document_option)
        self.model_option=QCheckBox('Use the signed malware-classification model')
        self.model_option.setChecked(options.get('model',True)); layout.addWidget(self.model_option)
        self.neural_option=QCheckBox('Use local MalConv2 neural byte analysis (CPU; slower)')
        self.neural_option.setChecked(options.get('neural',False));layout.addWidget(self.neural_option)
        self.reputation_option=QCheckBox('Use imported signed file/domain reputation')
        self.reputation_option.setChecked(options.get('reputation',False)); layout.addWidget(self.reputation_option)
        for control in (self.emulation_option,self.model_option,self.reputation_option,self.neural_option):
            control.toggled.connect(lambda checked:self.advanced_option.setChecked(True) if checked else None)
        self.advanced_option.toggled.connect(self.analysis_master_changed)
        self.amsi_option=QCheckBox('Inspect script files using installed Windows AMSI providers')
        self.amsi_option.setChecked(options.get('amsi',False))
        self.event_option=QCheckBox('Subscribe to process-start events; retain polling as reconciliation')
        self.event_option.setChecked(self.store.get('event_processes',True))
        for item in (self.archive_option,self.amsi_option,self.event_option): layout.addWidget(item)
        note=QLabel('AMSI is a consumer bridge to existing protection, not a registered SentinelAV provider.\nMemory inspection is read-only, limited to your account, and saves no raw memory.',objectName='small')
        note.setWordWrap(True); layout.addWidget(note)
        row=QHBoxLayout()
        self.memory_button=self.action(row,'Inspect Process Memory…',lambda:self.begin_bounded_inspection('memory'))
        self.prelaunch_button=self.action(row,'Check File Before Execution…',lambda:self.begin_bounded_inspection('file'))
        layout.addLayout(row)
        self.inspection_note=QLabel('No process memory or pre-execution inspection has run. Files are never launched here.',objectName='small')
        self.inspection_note.setWordWrap(True); layout.addWidget(self.inspection_note)
        row=QHBoxLayout(); self.action(row,'View Last Inspection',self.show_inspection_details); row.addStretch(); layout.addLayout(row)
        row=QHBoxLayout(); self.action(row,'Import Signed Model / Reputation…',self.import_analysis_artifact); layout.addLayout(row)
        row=QHBoxLayout(); self.action(row,'Dependency Status',self.show_feature_dependencies); layout.addLayout(row)
        layout.addStretch()
        inspection_scroll=QScrollArea(); inspection_scroll.setWidgetResizable(True); inspection_scroll.setWidget(page)
        tabs.addTab(inspection_scroll,'Inspection')
        page=QWidget(); layout=QVBoxLayout(page); layout.setContentsMargins(14,10,14,10)
        updates=self.store.get('artifact_updates',{})
        self.analysis_updates_option=QCheckBox('Check configured signed analysis feeds while monitoring')
        self.analysis_updates_option.setChecked(updates.get('enabled',False)); layout.addWidget(self.analysis_updates_option)
        layout.addWidget(QLabel('Model artifact HTTPS URL',objectName='small'))
        self.model_feed_url=QLineEdit(updates.get('urls',{}).get('model','')); layout.addWidget(self.model_feed_url)
        layout.addWidget(QLabel('Reputation artifact HTTPS URL',objectName='small'))
        self.reputation_feed_url=QLineEdit(updates.get('urls',{}).get('reputation','')); layout.addWidget(self.reputation_feed_url)
        layout.addWidget(QLabel('Signed fusion-policy update URL (optional)'))
        self.policy_feed_url=QLineEdit(updates.get('urls',{}).get('policy','')); layout.addWidget(self.policy_feed_url)
        row=QHBoxLayout(); self.action(row,'Pin Publisher…',self.pin_analysis_publisher); self.action(row,'Remove Publisher…',self.remove_analysis_publisher); layout.addLayout(row)
        self.collector_note=QLabel(self.store.get('kernel_collector','Native file-write collector: not configured'),objectName='small')
        self.collector_note.setWordWrap(True); layout.addWidget(self.collector_note)
        row=QHBoxLayout(); self.action(row,'Choose Protected Collector…',self.choose_kernel_collector); self.action(row,'Disconnect Collector',self.clear_kernel_collector); layout.addLayout(row)
        note=QLabel('Default is off. Checks run hourly during monitoring. Publishers must be separately trusted.\nOnly artifact downloads are sent; no files or scan contents are uploaded.\nSave and restart monitoring to apply. Experimental analysis remains a separate option.',objectName='small')
        note.setWordWrap(True); layout.addWidget(note)
        layout.addStretch()
        updates_scroll=QScrollArea(); updates_scroll.setWidgetResizable(True); updates_scroll.setWidget(page)
        tabs.addTab(updates_scroll,'Analysis Data')
        page=QWidget(); layout=QVBoxLayout(page); layout.setContentsMargins(14,10,14,10)
        from sentinelav.response.auto_response import policy_for
        policy=policy_for(self.store.get('auto_response',None))
        self.auto_response_option=QCheckBox('Enable automatic quarantine within the folders below')
        self.auto_response_option.setChecked(policy.get('enabled',False)); layout.addWidget(self.auto_response_option)
        self.high_confidence_option=QCheckBox('Quarantine high-confidence detections automatically (score 85+, not validly signed)')
        self.high_confidence_option.setChecked(policy.get('high_confidence',False)); layout.addWidget(self.high_confidence_option)
        self.calibrated_response_option=QCheckBox('Also allow calibrated unknown-threat quarantine after signed release gates pass')
        self.calibrated_response_option.setChecked(policy.get('allow_calibrated_unknown',False));layout.addWidget(self.calibrated_response_option)
        self.persistence_response_option=QCheckBox('Also disable directly attributed malicious HKCU startup entries after signed release gates pass')
        self.persistence_response_option.setChecked(policy.get('auto_persistence',False));layout.addWidget(self.persistence_response_option)
        layout.addWidget(QLabel('Approved SHA-256 hashes — one per line (maximum 256)',objectName='small'))
        self.response_hashes=QPlainTextEdit('\n'.join(policy.get('approved_hashes',[]))); self.response_hashes.setFixedHeight(45); layout.addWidget(self.response_hashes)
        layout.addWidget(QLabel('Allowed local folders — one per line (maximum 32; empty means the watched folders)',objectName='small'))
        self.response_roots=QPlainTextEdit('\n'.join(policy.get('roots',[]))); self.response_roots.setFixedHeight(45); layout.addWidget(self.response_roots)
        note=QLabel('Matches move to encrypted quarantine after a fresh scan confirms them, and can be restored.\nMaximum three attempts/minute; no automatic process termination or archive-member response.\nSave and restart to enable/change scope. Disabling stops queued actions; an active action may finish.',objectName='small')
        note.setWordWrap(True); layout.addWidget(note); layout.addStretch()
        response_scroll=QScrollArea();response_scroll.setWidgetResizable(True);response_scroll.setWidget(page);tabs.addTab(response_scroll,'Response Policy')
        self.last_inspection=None
        self.last_protection_state={}
        self.refresh_defense_layers()

    def refresh_defense_layers(self):
        """Fill the Layers table with an honest description of each protection layer's current state
        and its limits.
        """
        service=read_health()
        active=self.last_protection_state
        policy=self.store.get('auto_response',{})
        self.layer_details=[
            dict(layer='Windows service',state=service['state'],detail=service,remaining='Admin deployment/start is required. Install-ProtectionService.ps1 stages protected code/policy. Refresh and view these details for bounded recent service alerts. Existing per-user background mode remains separate.'),
            dict(layer='Process telemetry',state=active.get('process_event_source','Available; monitoring not verified'),remaining='WMI start events plus reconciliation polling; no guarantee of complete visibility.'),
            dict(layer='Script / AMSI',state='Consumer available; native provider not deployed',remaining='Native x64 provider and protected-service buffer broker are implemented for local harness testing. Signing, protected provider registration, real LocalService integration, and VM/host validation remain. No native provider is registered by the app; existing providers remain enabled.'),
            dict(layer='Pre-execution',state='Manual verdict only; global enforcement unavailable',remaining='System-wide interception needs reviewed native integration such as a signed minifilter; Windows SDK/WDK, signing, deployment and recovery validation are prerequisites. No driver is installed.'),
            dict(layer='Archives / formats',state='ZIP, PE structure and import capabilities',remaining='Bounded PE32/PE32+ import parsing; API capability combinations request review, not automatic quarantine. Delay imports and runtime-resolved APIs remain uncovered. ZIP: depth 2, 128 entries, 8 MiB/member, 32 MiB expansion, 100:1 ratio. Encrypted/unsupported content reports omissions.'),
            dict(layer='Memory inspection',state='Manual, same-account executable regions',remaining='32 MiB/128 regions/5-second scope. File-oriented rules can miss memory-only threats. Private executable memory may be legitimate JIT code.'),
            dict(layer='Behavior correlation',state=active.get('sequence_telemetry','Process ancestry; Sysmon sequence source not verified'),remaining='Ordered sequence checks use Sysmon ProcessGuid plus PID/image agreement. Existing Sysmon events 1, 3 and 13 and behavior monitoring must be enabled. Watchdog files are not attributed to processes. No automatic termination; broad efficacy is unvalidated.'),
            dict(layer='Installation / tamper',state='Protected deployment staged; per-user mode remains writable' if service['state']!='Running' else 'Service ACL deployment; no PPL/kernel protection',remaining='Service uses admin-owned Program Files/policy and startup integrity checks. No resistance to an administrator or kernel attacker is claimed.'),
            dict(layer='Containment policy',state='Active approved-hash quarantine' if active.get('automatic_response') else 'Configured; restart/verify monitoring' if policy.get('enabled') else 'Manual response; automatic policy off',remaining='Automatic actions require both an exact-hash detection and explicit hash/folder approval. Fresh scan, protected-path checks, encryption, audit, cooldown and rate limits apply.'),
            dict(layer='Scan worker isolation',state=active.get('inspection_isolation','Separate scan process with Windows job limits'),remaining='768 MiB job cap, two-process cap for venv compatibility, bounded JSON, timeouts and cancellation. Fault isolation is not a VM/AppContainer sandbox. Update conversion and trusted rule-review tooling have separate boundaries.')]
        self.fill(self.layer_table,[(r['layer'],r['state']) for r in self.layer_details])

    def show_layer_details(self,row,column):
        """Show a dialog with the full details of the double-clicked layer."""
        if 0<=row<len(self.layer_details):
            item=self.layer_details[row]
            box=QMessageBox(self); box.setWindowTitle(item['layer']); box.setText(item['state'])
            box.setInformativeText(item['remaining']); box.setDetailedText(json.dumps(item,indent=2)); box.exec()
