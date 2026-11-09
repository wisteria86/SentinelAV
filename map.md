# SentinelAV interaction map

Start with the workflow you want to change, then follow its arrows into the
smaller modules. Solid arrows show calls or data flow; dotted arrows show
composition. Paths below are relative to `src/sentinelav/` unless stated otherwise.

## Monitoring health and report evidence

```mermaid
flowchart LR
    Sources["watchdog / Sysmon / ETW / psutil"] --> Loop["monitoring/monitor_loop.py"]
    Loop -->|verify PID and creation time| Health["monitoring/health.py"]
    Health -->|verified process identity| Behavior["monitoring/behavior.py"]
    Health -->|persistent source failures and loss counts| Status["foreground worker / background IPC / service health"]
    Status --> UI["ui/protection_events.py"]
    UI -->|active or degraded| Dashboard["Dashboard"]
    UI -->|persist alerts and findings separately| DB["data/storage.py"]
    DB --> Reports["data/reporting.py"]
    Reports --> Sections["data/report_sections.py"]
    Sections --> Export["HTML evidence, coverage, and recovery tables"]
```

## 1. Entry points and process boundaries

```mermaid
flowchart TD
    Start["start.ps1 / app.py"] --> Entry["entrypoint.py"]
    Module["python -m sentinelav / __main__.py"] --> Entry
    Entry -->|desktop| Window["ui/application.py: Window"]
    Entry -->|--engine-host| Agent["monitoring/background.py"]
    Entry -->|--windows-service| Service["platform/windows_service.py"]
    Entry -->|--inspection-worker| Worker["detection/inspection_worker.py"]
    Entry -->|--qualification-job| Guest["lab/qualification/guest.py"]
    Window -->|scan requests| Parent["detection/inspection.py"]
    Parent -->|bounded JSON, separate process| Worker
    Window <-->|local JSON IPC| Protocol["monitoring/agent_protocol.py"]
    Protocol <--> Agent
    Agent --> Monitor["monitoring/monitoring.py"]
    Service --> Monitor
    Guest -->|typed cases in verified guests| Parent
```

## 2. User clicks Scan

```mermaid
sequenceDiagram
    actor User
    participant Page as ui/design_scan.py
    participant Actions as ui/scan_actions.py
    participant QtWorker as ui/application_workers.py
    participant Parent as detection/inspection.py
    participant Child as detection/inspection_worker.py
    participant Engine as detection/engine.py + scan_flow.py
    participant Store as data/storage.py
    User->>Page: Choose quick/custom scan
    Page->>Actions: start_scan(roots, kind)
    Actions->>QtWorker: Pass resource root, options and exclusions
    QtWorker->>Parent: scan(roots)
    Parent->>Child: Bounded JSON request
    Note over Parent,Child: worker_limits.py enforces process/memory limits;<br/>inspection_protocol.py supplies shared byte limits
    Child->>Engine: Analyze file identities and content
    Engine-->>Child: Findings, omissions and coverage
    Child-->>Parent: JSON response
    Parent-->>QtWorker: Scan result
    QtWorker-->>Actions: Progress / completed / failed signals
    Actions->>Store: Save history on GUI thread
    Actions-->>Page: Update progress and results
```

```mermaid
flowchart LR
    Scanner["detection/engine.py: Scanner"] -.-> Flow["scan_flow.py"]
    Flow --> Hash["signature_db.py"]
    Flow --> Yara["yara_rules.py"]
    Flow --> Archive["archive_inspection.py"]
    Flow --> Format["file_formats.py"]
    Flow --> Advanced["advanced_pipeline.py"]
    Advanced --> Content["content_analysis.py / active_content.py / documents.py"]
    Advanced --> Models["pe_classifier.py / pe_ensemble.py / neural_bytes.py"]
    Advanced --> Emulation["windows_emulation.py"]
    Emulation --> Adapters["speakeasy_backend.py / winapi_emulator.py"]
    Adapters -.-> Calls["emulated_calls.py / emulation_errors.py"]
    Advanced --> Fusion["decisions.py / fusion.py"]
    Fusion --> Result["data/contracts.py: analysis evidence and coverage"]
```

## 3. Continuous protection and App Changes

```mermaid
flowchart TD
    UI["ui/protection.py"] -->|start / stop / poll| IPC["monitoring/agent_protocol.py"]
    IPC <--> Agent["monitoring/background.py: EngineHost"]
    Agent --> Monitor["monitoring/monitoring.py: Monitor"]
    Monitor -.-> Loop["monitoring/monitor_loop.py"]
    Files["watchdog changes"] --> Sources["monitoring/event_sources.py"]
    Sysmon["Sysmon log"] --> Sources
    Sources -->|stabilized candidates| Loop
    Loop --> Processes["process_telemetry.py: identities and ancestry"]
    Loop --> Kernel["kernel_telemetry.py ↔ native/telemetry"]
    Loop --> Changes["change_monitor.py"]
    Changes --> Inventory["windows_inventory.py"]
    Changes --> Journal["data/change_journal.py"]
    Loop -->|same isolated scan pipeline| Inspect["detection/inspection.py"]
    Monitor --> Behavior["behavior.py / sequences.py"]
    Inspect --> Events["findings and coverage events"]
    Behavior --> Events
    Events --> Agent
    Agent --> History["data/storage.py"]
    Agent -->|poll responses| UIEvents["ui/protection_events.py"]
    Journal --> Timeline["ui/app_changes_ui.py"]
```

`monitoring/app_changes.py` remains the public import gateway to inventory and
change-monitoring code. It does not run a second implementation.

## 4. Reviewed response and recovery

```mermaid
flowchart LR
    Results["Scan results / App Changes"] --> Pages["ui/response_pages.py"]
    Pages --> Actions["ui/response_actions.py + response_ui.py"]
    Actions --> Qt["ui/response_ui_workers.py"]
    Qt --> Files["response/response.py: ResponseService"]
    Files --> Guards["response/response_files.py"]
    Files --> Vault["Encrypted quarantine + audit history"]
    Actions --> Plan["response/remediation.py: Remediator"]
    Plan --> Parse["remediation_resources.py"]
    Plan --> Journal["data/change_journal.py"]
    Plan --> Backend["remediation_backend.py"]
    Backend --> Inventory["monitoring/windows_inventory.py"]
    Backend --> Verify["Re-read current state / verify remnants"]
    Plan -->|protected actions require authorization| Broker["platform/remediation_broker.py"]
    Verify --> Receipt["RemediationReceipt"]
    Receipt --> Actions
```

## 5. Signed update flow

```mermaid
flowchart LR
    UI["ui/updates_ui.py / defense_settings.py"] --> Import["updates/definition_updates.py"]
    Import --> Envelope["update_envelope.py: bounds, format and signature checks"]
    Import --> Snapshots["hash_snapshots.py: lock and atomic activation"]
    Snapshots --> Index["detection/signature_db.py"]
    Models["Signed analysis imports"] --> Artifacts["updates/artifacts.py / analysis_trust.py"]
    Agent["updates/agent.py"] --> Artifacts
    Artifacts --> Pipeline["detection/advanced_pipeline.py"]
    Index --> Scanner["detection/engine.py"]
```

## 6. Evaluation harness: host and guest stay separate

```mermaid
flowchart TD
    Launcher["Run-SentinelAV-Tests.cmd"] --> CLI["tools/evaluation/launch_critical.py → critical_harness.py"]
    CLI --> Runner["lab/qualification/runner.py"]
    Runner --> Environment["evaluation_environment.py"]
    Environment --> Workspace["workspace.py → F: builds, datasets and kits"]
    Runner --> Queue["store.py: durable queue"]
    Runner --> Cases["catalog.py + contracts.py"]
    Runner --> Sandbox["backend_sandbox.py"]
    Runner --> VM["backend_hyperv.py"]
    Sandbox -.-> Transport["backend_transport.py"]
    VM -.-> Transport
    Transport --> Control["backend_control.py"]
    Transport -->|typed jobs / bounded evidence| Guest["guest.py"]
    Guest --> Context["guest_context.py: offline guest checks"]
    Guest --> Support["guest_support.py: fixtures and engine setup"]
    Support --> Token["guest_process.py: restricted engine process"]
    Guest --> Telemetry["guest_telemetry.py → telemetry.py"]
    Guest --> Zoo["zoo_guest.py → signature-free inspection worker"]
    ZooInventory["zoo_inventory.py → pinned Git tree and encrypted batch"] --> Zoo
    Zoo --> ZooReport["zoo_reporting.py → resumable run report and ledger"]
    Telemetry --> Writer["probe_writer.py → dedicated harmless file writer"]
    Telemetry --> Native["native/telemetry collector + Sysmon"]
    Guest --> Lifecycle["guest_lifecycle.py"]
    Guest --> Corpus["guest_inventory.py"]
    Corpus --> Inputs["corpus_inputs.py"]
    Corpus --> Cleanup["cleanup_fixtures.py"]
    Inputs --> Scan["shared detection pipeline"]
    Runner --> Scorer["scoring.py"]
    Scorer --> Reports["reporting.py / comparison.py"]
    Reports --> Logs["project logs/run-id/report.md and JSON ledgers"]
    Sandbox --> Disposal["Owned guest disposal receipt"]
    VM --> Disposal
    Queue -->|interrupted run| Recover["backend_recovery.py"]
    Recover -->|reconcile ownership before resume| Disposal
```

The public `backends.py` gateway exports the backend classes; their implementations
live in the focused `backend_*` files. This is a code interaction map, not a claim
that every qualification track has passed.

## 7. How UI files compose one window

```mermaid
flowchart TD
    Window["application.py: Window"] -.-> Base["application.py: BaseWindow"]
    Base -.-> ScanActions["scan_actions.py"]
    Base -.-> Widgets["window_widgets.py"]
    Window -.-> Design["design.py"]
    Design -.-> Shell["design_shell.py"]
    Design -.-> Dashboard["design_dashboard.py"]
    Design -.-> Scan["design_scan.py"]
    Design -.-> Reports["design_reports.py"]
    Design -.-> Settings["design_settings.py"]
    Shell --> Components["design_components.py"]
    Dashboard --> Components
    Scan --> Components
    Reports --> Components
    Settings --> Components
    Window -.-> Protection["protection.py"]
    Protection -.-> ProtectionPages["protection_pages.py"]
    Protection -.-> ProtectionEvents["protection_events.py"]
    Window -.-> Response["response_ui.py"]
    Response -.-> ResponsePages["response_pages.py"]
    Response -.-> ResponseActions["response_actions.py"]
    Window -.-> Defense["defense_ui.py"]
    Defense -.-> DefensePages["defense_pages.py"]
    Defense -.-> DefenseSettings["defense_settings.py"]
    Window -.-> Lab["lab_ui.py → lab_pages.py"]
```

Page mixins operate on the same `Window` instance. Shared controls and state are
initialized by `BaseWindow`; feature hooks continue through `super()`. Workers
emit signals back to the UI, which owns its SQLite connection.

## 8. Optional native integrations and their boundaries

```mermaid
flowchart LR
    AMSI["Windows AMSI host"] -.->|requires deployed provider| Provider["native/amsi/provider.cpp + provider.h"]
    Provider -->|bounded local buffer request| Broker["platform/amsi_broker.py"]
    Broker --> Buffer["detection/buffer_scan.py / inspection.py"]
    Harness["native/amsi/harness.cpp + probe.cpp"] -->|inert integration fixtures| Provider
    Build["tools/build_emulator.py + native/emulator patch"] --> Runtime["validated Unicorn runtime"]
    Runtime --> Support["platform/emulation_support.py"]
    Support --> Emulation["detection/windows_emulation.py"]
    CollectorBuild["scripts/Build-KernelCollector.ps1"] --> Collector["native/telemetry/Program.cs"]
    Collector -->|read-only kernel events| Events["monitoring/kernel_telemetry.py"]
    Events --> Product["monitoring/monitor_loop.py"]
    Events --> Evaluation["lab/qualification/telemetry.py"]
```

Native deployment and actual collection still have their own permission and
validation gates. This refactor does not change those requirements.

## 9. Detailed module interactions

Expand a package below to follow its actual first-party imports. These edges
mean **imports/uses**, including imports inside functions; they do not imply
startup execution order. External libraries and vendor code are omitted.

<details><summary>data: actual module imports</summary>

```mermaid
flowchart LR
  m0["change_journal.py"]
  m1["contracts.py"]
  m2["reporting.py"]
  m3["storage.py"]
  m0 --> m1
```

</details>

<details><summary>detection: actual module imports</summary>

```mermaid
flowchart LR
  m0["active_content.py"]
  m1["advanced_pipeline.py"]
  m2["anomaly_model.py"]
  m3["archive_inspection.py"]
  m4["buffer_scan.py"]
  m5["classifier.py"]
  m6["content_analysis.py"]
  m7["decisions.py"]
  m8["delay_imports.py"]
  m9["documents.py"]
  m10["emulated_calls.py"]
  m11["emulation.py"]
  m12["emulation_errors.py"]
  m13["engine.py"]
  m14["file_formats.py"]
  m15["fusion.py"]
  m16["image_details.py"]
  m17["inspection.py"]
  m18["inspection_protocol.py"]
  m19["inspection_worker.py"]
  m20["memory_inspection.py"]
  m21["neural_bytes.py"]
  m22["pe_classifier.py"]
  m23["pe_ensemble.py"]
  m24["pe_image.py"]
  m25["pe_imports.py"]
  m26["preexecution.py"]
  m27["reputation.py"]
  m28["scan_flow.py"]
  m29["signature_db.py"]
  m30["speakeasy_backend.py"]
  m31["winapi_emulator.py"]
  m32["windows_emulation.py"]
  m33["worker_limits.py"]
  m34["yara_rules.py"]
  m1 --> m0
  m1 --> m5
  m1 --> m6
  m1 --> m7
  m1 --> m9
  m1 --> m11
  m1 --> m21
  m1 --> m22
  m1 --> m23
  m1 --> m27
  m5 --> m2
  m5 --> m22
  m5 --> m23
  m7 --> m15
  m8 --> m24
  m10 --> m12
  m11 --> m30
  m11 --> m32
  m13 --> m1
  m13 --> m3
  m13 --> m14
  m13 --> m28
  m13 --> m29
  m13 --> m34
  m14 --> m8
  m14 --> m16
  m14 --> m25
  m16 --> m24
  m17 --> m4
  m17 --> m18
  m17 --> m19
  m17 --> m33
  m19 --> m4
  m19 --> m13
  m19 --> m18
  m19 --> m20
  m20 --> m34
  m23 --> m22
  m28 --> m3
  m28 --> m7
  m28 --> m14
  m31 --> m10
  m31 --> m12
  m32 --> m24
  m32 --> m31
```

</details>

<details><summary>monitoring: actual module imports</summary>

```mermaid
flowchart LR
  m0["agent_protocol.py"]
  m1["app_changes.py"]
  m2["background.py"]
  m3["behavior.py"]
  m4["change_monitor.py"]
  m5["event_sources.py"]
  m6["kernel_telemetry.py"]
  m7["monitor_loop.py"]
  m8["monitoring.py"]
  m9["process_telemetry.py"]
  m10["sequences.py"]
  m11["windows_inventory.py"]
  m1 --> m4
  m1 --> m11
  m2 --> m0
  m2 --> m8
  m4 --> m10
  m4 --> m11
  m7 --> m1
  m7 --> m3
  m7 --> m5
  m7 --> m6
  m7 --> m9
  m8 --> m3
  m8 --> m5
  m8 --> m7
  m8 --> m9
  m8 --> m10
```

</details>

<details><summary>response: actual module imports</summary>

```mermaid
flowchart LR
  m0["auto_response.py"]
  m1["change_reports.py"]
  m2["containment.py"]
  m3["remediation.py"]
  m4["remediation_backend.py"]
  m5["remediation_resources.py"]
  m6["response.py"]
  m7["response_files.py"]
  m8["transaction.py"]
  m0 --> m3
  m0 --> m6
  m2 --> m6
  m3 --> m4
  m3 --> m5
  m3 --> m6
  m4 --> m5
  m4 --> m6
  m6 --> m2
  m6 --> m7
```

</details>

<details><summary>platform: actual module imports</summary>

```mermaid
flowchart LR
  m0["amsi_broker.py"]
  m1["amsi_client.py"]
  m2["emulation_support.py"]
  m3["engine_policy.py"]
  m4["feature_status.py"]
  m5["integrity.py"]
  m6["remediation_broker.py"]
  m7["runtime.py"]
  m8["service_changes.py"]
  m9["windows_identity.py"]
  m10["windows_service.py"]
  m0 --> m9
  m4 --> m2
  m6 --> m0
  m6 --> m5
  m6 --> m8
  m6 --> m9
  m6 --> m10
  m8 --> m5
  m8 --> m9
  m8 --> m10
  m10 --> m0
  m10 --> m3
  m10 --> m5
  m10 --> m9
```

</details>

<details><summary>updates: actual module imports</summary>

```mermaid
flowchart LR
  m0["agent.py"]
  m1["analysis_trust.py"]
  m2["artifacts.py"]
  m3["definition_updates.py"]
  m4["hash_archive.py"]
  m5["hash_snapshots.py"]
  m6["update_envelope.py"]
  m0 --> m2
  m1 --> m2
  m3 --> m4
  m3 --> m5
  m3 --> m6
  m4 --> m3
  m5 --> m4
  m5 --> m6
  m6 --> m4
```

</details>

<details><summary>ui: actual module imports</summary>

```mermaid
flowchart LR
  m0["app_changes_ui.py"]
  m1["application.py"]
  m2["application_workers.py"]
  m3["background_ui.py"]
  m4["defense_pages.py"]
  m5["defense_settings.py"]
  m6["defense_ui.py"]
  m7["defense_ui_workers.py"]
  m8["design.py"]
  m9["design_components.py"]
  m10["design_dashboard.py"]
  m11["design_reports.py"]
  m12["design_scan.py"]
  m13["design_settings.py"]
  m14["design_shell.py"]
  m15["finalization.py"]
  m16["lab_pages.py"]
  m17["lab_ui.py"]
  m18["lab_ui_workers.py"]
  m19["protection.py"]
  m20["protection_events.py"]
  m21["protection_pages.py"]
  m22["protection_workers.py"]
  m23["response_actions.py"]
  m24["response_pages.py"]
  m25["response_ui.py"]
  m26["response_ui_workers.py"]
  m27["runtime_ui.py"]
  m28["scan_actions.py"]
  m29["updates_ui.py"]
  m30["window_widgets.py"]
  m31["yara_ui.py"]
  m1 --> m0
  m1 --> m2
  m1 --> m6
  m1 --> m8
  m1 --> m15
  m1 --> m17
  m1 --> m19
  m1 --> m25
  m1 --> m28
  m1 --> m29
  m1 --> m30
  m1 --> m31
  m5 --> m1
  m6 --> m1
  m6 --> m4
  m6 --> m5
  m6 --> m7
  m8 --> m9
  m8 --> m10
  m8 --> m11
  m8 --> m12
  m8 --> m13
  m8 --> m14
  m10 --> m9
  m11 --> m9
  m12 --> m9
  m14 --> m9
  m16 --> m18
  m16 --> m27
  m17 --> m1
  m17 --> m8
  m17 --> m16
  m17 --> m18
  m19 --> m1
  m19 --> m3
  m19 --> m8
  m19 --> m20
  m19 --> m21
  m19 --> m22
  m24 --> m1
  m25 --> m1
  m25 --> m23
  m25 --> m24
  m25 --> m26
  m28 --> m2
  m29 --> m1
  m31 --> m1
```

</details>

<details><summary>lab: actual module imports</summary>

```mermaid
flowchart LR
  m0["advanced_check.py"]
  m1["corpus_evaluation.py"]
  m2["emulation_evaluation.py"]
  m3["lab.py"]
  m4["removal_benchmark.py"]
  m5["response_check.py"]
  m6["runtime_job.py"]
  m7["static_corpus.py"]
  m8["static_pilot.py"]
  m6 --> m1
  m7 --> m1
  m7 --> m2
  m7 --> m8
  m8 --> m1
```

</details>

<details><summary>lab.qualification: actual module imports</summary>

```mermaid
flowchart LR
  m0["backend_control.py"]
  m1["backend_hyperv.py"]
  m2["backend_recovery.py"]
  m3["backend_sandbox.py"]
  m4["backend_transport.py"]
  m5["backends.py"]
  m6["catalog.py"]
  m7["cleanup_fixtures.py"]
  m8["comparison.py"]
  m9["contracts.py"]
  m10["corpus_inputs.py"]
  m11["disk_pressure.py"]
  m12["evaluation_environment.py"]
  m13["features.py"]
  m14["guest.py"]
  m15["guest_context.py"]
  m16["guest_inventory.py"]
  m17["guest_lifecycle.py"]
  m18["guest_process.py"]
  m19["guest_support.py"]
  m20["guest_telemetry.py"]
  m21["inventories.py"]
  m22["reporting.py"]
  m23["runner.py"]
  m24["scoring.py"]
  m25["store.py"]
  m26["telemetry.py"]
  m1 --> m0
  m1 --> m3
  m1 --> m9
  m1 --> m25
  m2 --> m1
  m2 --> m3
  m3 --> m0
  m3 --> m4
  m3 --> m25
  m4 --> m0
  m4 --> m9
  m4 --> m22
  m4 --> m25
  m5 --> m0
  m5 --> m1
  m5 --> m2
  m5 --> m3
  m6 --> m9
  m10 --> m15
  m10 --> m19
  m11 --> m14
  m12 --> m5
  m12 --> m9
  m12 --> m24
  m12 --> m25
  m13 --> m24
  m14 --> m9
  m14 --> m15
  m14 --> m16
  m14 --> m17
  m14 --> m19
  m14 --> m20
  m14 --> m22
  m16 --> m5
  m16 --> m7
  m16 --> m9
  m16 --> m10
  m16 --> m15
  m17 --> m15
  m17 --> m19
  m17 --> m22
  m17 --> m26
  m18 --> m15
  m19 --> m6
  m19 --> m15
  m19 --> m18
  m20 --> m5
  m20 --> m11
  m20 --> m15
  m20 --> m19
  m20 --> m22
  m20 --> m26
  m21 --> m9
  m21 --> m24
  m22 --> m8
  m22 --> m9
  m22 --> m24
  m22 --> m25
  m23 --> m5
  m23 --> m6
  m23 --> m8
  m23 --> m9
  m23 --> m12
  m23 --> m13
  m23 --> m21
  m23 --> m22
  m23 --> m24
  m23 --> m25
  m24 --> m9
  m25 --> m9
```

</details>

<details><summary>tools.feeds: CLI imports and their source modules</summary>

```mermaid
flowchart LR
  t0["sentinelav.data.storage"]
  t1["sentinelav.detection.neural_bytes"]
  t2["sentinelav.detection.pe_classifier"]
  t3["sentinelav.detection.pe_ensemble"]
  t4["sentinelav.paths"]
  t5["sentinelav.platform.engine_policy"]
  t6["sentinelav.response.response"]
  t7["sentinelav.updates.analysis_trust"]
  t8["sentinelav.updates.artifacts"]
  t9["sentinelav.updates.definition_updates"]
  t10["sentinelav.updates.hash_archive"]
  t11["sentinelav.workspace"]
  t12["tools.feeds.download_hashes"]
  t13["tools.feeds.enable_learned_detection"]
  t14["tools.feeds.import_hash_archive"]
  t15["tools.feeds.install_benchmark_models"]
  t16["tools.feeds.install_neural_model"]
  t17["tools.feeds.install_reviewed_yara"]
  t18["tools.feeds.install_zeus_rules"]
  t19["tools.feeds.manage_artifacts"]
  t20["tools.feeds.manage_definitions"]
  t12 --> t4
  t12 --> t9
  t13 --> t0
  t13 --> t4
  t13 --> t5
  t13 --> t7
  t13 --> t8
  t13 --> t11
  t14 --> t10
  t15 --> t2
  t15 --> t3
  t15 --> t4
  t15 --> t6
  t15 --> t7
  t15 --> t8
  t15 --> t11
  t16 --> t1
  t16 --> t4
  t16 --> t11
  t17 --> t4
  t18 --> t4
  t19 --> t8
  t20 --> t9
```

</details>

<details><summary>tools.evaluation: CLI imports and their source modules</summary>

```mermaid
flowchart LR
  t0["sentinelav.data.storage"]
  t1["sentinelav.detection.anomaly_model"]
  t2["sentinelav.detection.classifier"]
  t3["sentinelav.detection.engine"]
  t4["sentinelav.detection.fusion"]
  t5["sentinelav.detection.pe_classifier"]
  t6["sentinelav.detection.pe_ensemble"]
  t7["sentinelav.lab.corpus_evaluation"]
  t8["sentinelav.lab.lab"]
  t9["sentinelav.lab.qualification.backends"]
  t10["sentinelav.lab.qualification.runner"]
  t11["sentinelav.lab.qualification.store"]
  t12["sentinelav.lab.removal_benchmark"]
  t13["sentinelav.lab.runtime_job"]
  t14["sentinelav.lab.static_corpus"]
  t15["sentinelav.lab.static_pilot"]
  t16["sentinelav.monitoring.behavior"]
  t17["sentinelav.monitoring.monitoring"]
  t18["sentinelav.paths"]
  t19["sentinelav.platform.emulation_support"]
  t20["sentinelav.platform.engine_policy"]
  t21["sentinelav.response.containment"]
  t22["sentinelav.response.response"]
  t23["sentinelav.updates.artifacts"]
  t24["sentinelav.workspace"]
  t25["tools.evaluation.acquire_corpus"]
  t26["tools.evaluation.acquire_features"]
  t27["tools.evaluation.acquire_pilot"]
  t28["tools.evaluation.aggregate_signature_free"]
  t29["tools.evaluation.audit_learned_zoo"]
  t30["tools.evaluation.benchmark"]
  t31["tools.evaluation.calibrate_static"]
  t32["tools.evaluation.compare_removal"]
  t33["tools.evaluation.critical_harness"]
  t34["tools.evaluation.evaluate_behavior"]
  t35["tools.evaluation.evaluate_benign"]
  t36["tools.evaluation.evaluate_corpus"]
  t37["tools.evaluation.evaluate_coverage"]
  t38["tools.evaluation.evaluate_published_ensemble"]
  t39["tools.evaluation.inspect_corpus_metadata"]
  t40["tools.evaluation.inspect_zeus_rule_sources"]
  t41["tools.evaluation.launch_critical"]
  t42["tools.evaluation.prepare_features"]
  t43["tools.evaluation.prepare_signature_free"]
  t44["tools.evaluation.process_tree_response"]
  t45["tools.evaluation.run_guest_job"]
  t46["tools.evaluation.run_learned_zoo"]
  t47["tools.evaluation.setup_lab_telemetry"]
  t48["tools.evaluation.train_classifier"]
  t49["tools.evaluation.train_pe_model"]
  t50["tools.evaluation.verify_frozen_emulator"]
  t51["tools.evaluation.verify_learned_package"]
  t25 --> t14
  t25 --> t18
  t25 --> t22
  t25 --> t24
  t26 --> t24
  t27 --> t15
  t27 --> t18
  t27 --> t22
  t27 --> t24
  t28 --> t7
  t28 --> t23
  t28 --> t24
  t29 --> t46
  t30 --> t3
  t30 --> t17
  t30 --> t18
  t31 --> t1
  t32 --> t12
  t32 --> t23
  t32 --> t24
  t33 --> t9
  t33 --> t10
  t33 --> t11
  t33 --> t18
  t34 --> t8
  t34 --> t16
  t34 --> t18
  t35 --> t3
  t35 --> t18
  t35 --> t20
  t35 --> t24
  t36 --> t7
  t37 --> t7
  t37 --> t18
  t37 --> t20
  t37 --> t24
  t38 --> t6
  t38 --> t18
  t38 --> t22
  t38 --> t23
  t38 --> t24
  t39 --> t14
  t41 --> t33
  t42 --> t24
  t42 --> t26
  t43 --> t4
  t43 --> t7
  t43 --> t18
  t43 --> t23
  t43 --> t24
  t44 --> t0
  t44 --> t18
  t44 --> t21
  t44 --> t22
  t44 --> t23
  t45 --> t13
  t45 --> t23
  t46 --> t14
  t46 --> t22
  t46 --> t24
  t47 --> t9
  t47 --> t11
  t47 --> t18
  t47 --> t24
  t48 --> t2
  t48 --> t23
  t49 --> t5
  t49 --> t24
  t50 --> t19
  t51 --> t6
  t51 --> t18
  t51 --> t23
  t51 --> t24
```

</details>
