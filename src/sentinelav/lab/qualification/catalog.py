# Purpose: Frozen test catalog; missing independent inventories remain mandatory cases.
# Works with: lab.qualification.contracts
# Used by: lab.qualification.guest_support, lab.qualification.runner, tests.unit.harness_fixtures,
#   tests.unit.test_critical_harness

"""Frozen test catalog; missing independent inventories remain mandatory cases."""
from dataclasses import asdict
from .contracts import CaseDefinition,SuiteManifest

FUNCTIONAL={
 'harness':['test_runtime_guards','test_signature_free','test_signature_free_aggregation'],
 'monitoring':['test_monitoring','test_sequences','test_app_changes'],
 'cleanup':['test_response','test_remediation_transactions','test_tree_containment','test_remediation_broker'],
 'reliability':['test_background','test_runtime_guards','test_integrated_analysis'],
 'updates':['test_analysis_artifacts','test_definition_updates'],
}


def suite(run_id,profile,versions,inventories=None):
    """Build the full list of evaluation cases for a run profile (regression, critical, soak, ...),
    with their budgets.

    Each case names its track, where it runs (host, Sandbox or Hyper-V), what it does, and what
    result is expected.
    """
    cases=[]
    def add(id,track,backend,action,**kw):
        """Append one validated case definition."""
        cases.append(asdict(CaseDefinition(id,track,backend,action,**kw)))
    add('scorer-known-answers','harness','host','selfcheck',expected=dict(assertions_passed=True))
    for track,names in FUNCTIONAL.items():
        add('functional-'+track,track,'sandbox','functional',parameters=dict(modules=names),expected=dict(failures=0,tests_executed=True))
    add('package-baseline','deployment','sandbox','selftest',expected=dict(selftest_passed=True))
    for mode in ('signature_free','normal'):
        for group in ('base','holdout','zeus'):
            add('inspect-'+group+'-'+mode,'raw_detection','sandbox','inspect',mode=mode,parameters=dict(group=group),expected=dict(identity_checks_passed=True))
    add('frozen-dotnet-regression','classification','host','feature_regression',seconds=1800,expected=dict(benchmark_completed=True))
    add('legitimate-file-controls','false_alarms','sandbox','benign',expected=dict(false_confirmed=0))
    if profile!='regression':
        for fmt in ('Win32','Win64','Dot_Net'):
            add('qualification-'+fmt,'classification','host','feature_qualification',seconds=3600,parameters=dict(format=fmt),expected=dict(benchmark_completed=True))
        for mode in ('signature_free','normal'):
            for sample in ('wannacry','emotet','zeusvm','wannacryplus','gameover','zeusbanking','gameoveralt'):
                add('live-'+sample+'-'+mode,'prevention','sandbox','live',mode=mode,parameters=dict(sample=sample),expected=dict(protection_verified=True))
        for name,track in [('family-disjoint','generalization'),('independent-raw-corpus','raw_detection'),('legitimate-app-workflows','false_alarms'),('automatic-action-controls','automatic_safety')]:
            add(name,track,'hyperv','inventory',seconds=3600,parameters=dict(inventory=name),expected=dict(qualification_evidence=True))
        cases[-4]['backend']='host';cases[-4]['action']='family_qualification'
        add('independent-raw-corpus-signature-free','raw_detection','hyperv','inventory',mode='signature_free',seconds=3600,
            parameters=dict(inventory='independent-raw-corpus'),expected=dict(qualification_evidence=True))
        add('telemetry-loss-probes','monitoring','sandbox','telemetry',expected=dict(probes_passed=True,loss_failure_detected=True))
        add('vm-install-upgrade-repair-uninstall','deployment','hyperv','deployment',seconds=1800,expected=dict(lifecycle_verified=True))
        add('vm-cleanup-two-reboots','recurrence','hyperv','recurrence',seconds=3600,expected=dict(reboots_verified=2,protected_controls_changed=0,malicious_remnants=0))
        add('vm-cleanup-artifacts','cleanup','hyperv','inventory',parameters=dict(inventory='remediation-cases'),expected=dict(qualification_evidence=True))
        add('vm-tracked-cleanup-artifacts','cleanup','hyperv','inventory',parameters=dict(inventory='remediation-cases',scenario='tracked'),expected=dict(qualification_evidence=True))
        add('vm-tracked-cleanup-two-reboots','recurrence','hyperv','recurrence',seconds=3600,parameters=dict(inventory='recurrence',scenario='tracked'),expected=dict(reboots_verified=2,protected_controls_changed=0,malicious_remnants=0))
        add('vm-recovery-faults','reliability','hyperv','recovery',seconds=1800,expected=dict(recovery_verified=True))
        add('vm-paired-performance','performance','hyperv','performance',seconds=3600,expected=dict(pairs=5,budgets_passed=True))
        add('vm-soak-24h','soak','hyperv','soak',seconds=86400,expected=dict(soak_verified=True))
        add('defender-paired-comparison','comparison','hyperv','comparison',required=False,seconds=3600,expected=dict(superiority_gate_passed=True))
    return asdict(SuiteManifest(run_id,profile,versions,cases,dict(total_seconds=604800+7200 if profile=='soak' else 7200,
        system_reserve_bytes=2*1024**3,sandbox_system_reserve_bytes=10*1024**3,work_reserve_bytes=20*1024**3,log_limit_bytes=1024**3,
        worker_memory_bytes=1024**3,runtime_processes=32,performance=dict(max_workload_slowdown=.15,
        max_idle_cpu_percent=1.0,max_idle_rss_bytes=512*1024**2),max_guest_export_bytes=65536),inventories or {}))
