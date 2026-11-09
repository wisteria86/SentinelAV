# Purpose: One-click critical evaluation entry point and optional local progress window.
# Works with: lab.qualification.backends, lab.qualification.runner, lab.qualification.store, paths
# Used by: tests.ui.verify_critical_harness_ui, tools.evaluation.launch_critical

"""One-click critical evaluation entry point and optional local progress window."""
import argparse
import json
import os
from pathlib import Path
import sys
import threading
from sentinelav.paths import PROJECT_ROOT
from sentinelav.lab.qualification.runner import Runner


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=('regression','critical','soak','zoo-static','zoo-quick'),default='critical')
    parser.add_argument('--headless',action='store_true')
    parser.add_argument('--preflight-only',action='store_true')
    parser.add_argument('--resume',type=Path)
    parser.add_argument('--release-soak',action='store_true')
    parser.add_argument('--host-only',action='store_true',help='Run safe metadata/feature checks and block all guest cases')
    args=parser.parse_args(argv)
    if args.headless:
        path,summary=Runner(PROJECT_ROOT,args.profile,resume=args.resume,preflight_only=args.preflight_only,release_soak=args.release_soak,host_only=args.host_only).run()
        print(json.dumps(dict(report=str(path/'report.md'),qualification=summary['status'])))
        return 0 if summary['status']=='passed' else 2
    from PySide6.QtCore import QThread,Signal
    from PySide6.QtWidgets import QApplication,QWidget,QVBoxLayout,QLabel,QPushButton,QPlainTextEdit,QComboBox,QProgressBar
    cancel=threading.Event()
    class Worker(QThread):
        update=Signal(str);queue_progress=Signal(int,int);finished_run=Signal(str,str);failed=Signal(str)
        def run(self):
            try:
                if getattr(self,'prepare_telemetry',False):
                    self.update.emit('Preparing Microsoft-signed guest telemetry; no host collector installation')
                    from sentinelav.lab.qualification.backends import run
                    try:run([sys.executable,'-m','tools.evaluation.setup_lab_telemetry','--accept-sysmon-eula'],900,cancel.is_set)
                    except Exception as e:self.update.emit('Telemetry setup incomplete: '+str(e)+'. Dependent cases will be reported blocked.')
                path,summary=Runner(PROJECT_ROOT,self.selected_profile,cancel.is_set,self.update.emit,args.resume,args.preflight_only,args.release_soak,args.host_only,queue_progress=self.queue_progress.emit).run()
                self.finished_run.emit(str(path/'report.md'),summary['status'])
            except Exception as e:self.failed.emit(type(e).__name__+': '+str(e))
    app=QApplication.instance() or QApplication([])
    from PySide6.QtGui import QFontDatabase
    for font in ('segoeui.ttf','segoeuib.ttf','seguisb.ttf'):QFontDatabase.addApplicationFont(str(Path(os.environ.get('WINDIR','C:/Windows'))/'Fonts'/font))
    app.setStyle('Fusion')
    window=QWidget();window.setWindowTitle('SentinelAV — Critical Evaluation');window.resize(740,500)
    window.setStyleSheet('QWidget{background:#fff7e9;color:#302217;font:14px "Segoe UI"} QPushButton{background:#ef842b;border:1px solid #d47725;border-radius:5px;padding:8px} QPushButton:disabled{background:#ecdfce;color:#8f8174;border-color:#d9c9b8} QPlainTextEdit{background:#fffaf2;border:1px solid #d9c9b8}')
    layout=QVBoxLayout(window);layout.addWidget(QLabel('Critical evaluation — evidence and failures, never a synthetic protection score'))
    profile=QComboBox();profile.addItems(['critical','regression','soak','zoo-static','zoo-quick']);profile.setCurrentText(args.profile);layout.addWidget(profile)
    status=QLabel('Ready to start');status.setWordWrap(True);layout.addWidget(status)
    bar=QProgressBar();bar.setValue(0)
    bar.setStyleSheet('QProgressBar{border:1px solid #d9c9b8;border-radius:5px;text-align:center} QProgressBar::chunk{background:#ef842b;border-radius:4px}')
    layout.addWidget(bar)
    log=QPlainTextEdit();log.setReadOnly(True);log.setMaximumBlockCount(1000);layout.addWidget(log)
    start=QPushButton('Start evaluation');stop=QPushButton('Cancel and preserve evidence');open_report=QPushButton('Open report');open_report.setEnabled(False)
    for widget in (start,stop,open_report):layout.addWidget(widget)
    worker=Worker();report=[None];closing=[False]
    def launch():
        from PySide6.QtWidgets import QMessageBox
        support=Path(os.environ.get('SENTINELAV_WORK_ROOT','F:/SentinelAV-Work'))/'lab/qualification/support/manifest.json'
        worker.prepare_telemetry=False
        if not profile.currentText().startswith('zoo-') and not args.preflight_only and not args.host_only and not support.exists():
            dialog=QMessageBox(window);dialog.setWindowTitle('First-time guest telemetry setup')
            dialog.setText('Sysmon requires Microsoft Sysinternals license acceptance. It will be downloaded, signature-checked, and installed only inside disposable test guests.\n\nTerms: https://learn.microsoft.com/sysinternals/license-terms\n\nAccept and prepare the lab package? Choosing No continues with telemetry-dependent cases blocked.')
            dialog.setStandardButtons(QMessageBox.Yes|QMessageBox.No)
            worker.prepare_telemetry=dialog.exec()==QMessageBox.Yes
        worker.selected_profile=profile.currentText()
        cancel.clear();profile.setEnabled(False);start.setEnabled(False);stop.setEnabled(True)
        status.setText('Starting evaluation…');bar.setRange(0,0);worker.start()
    def done(path,outcome):
        report[0]=path;open_report.setEnabled(True);log.appendPlainText('Report saved: '+path);stop.setEnabled(False)
        from sentinelav.lab.qualification.store import RunStore
        store=RunStore(Path(path).parent)
        try:pending=bool(store.pending())
        finally:store.close()
        if pending:
            status.setText('Paused · remaining work can be resumed. Open the report for details.')
            args.resume=Path(path).parent;start.setText('Resume remaining cases');start.setEnabled(True)
        else:
            status.setText('Run ended · '+outcome.capitalize()+'. Open the report for details.')
        if bar.maximum()==0:bar.setRange(0,1);bar.setValue(0)
    def failed(text):
        status.setText(text);bar.setRange(0,1);bar.setValue(0);stop.setEnabled(False)
        log.appendPlainText(text);log.appendPlainText('Any created run folder retains its report and queue.');start.setEnabled(True);profile.setEnabled(True)
    def update(text):
        log.appendPlainText(text)
        if not cancel.is_set():status.setText(text)
    def update_queue(completed,total):
        unit='batches' if worker.selected_profile.startswith('zoo-') else 'cases'
        bar.setRange(0,total);bar.setFormat(f'{completed} / {total} {unit} recorded');bar.setValue(completed)
    def stop_run():
        cancel.set();stop.setEnabled(False);status.setText('Cancelling · waiting for guest cleanup…')
    def close(event):
        if worker.isRunning():closing[0]=True;stop_run();event.ignore()
        else:event.accept()
    window.closeEvent=close;start.clicked.connect(launch);stop.clicked.connect(stop_run)
    open_report.clicked.connect(lambda:os.startfile(report[0]) if report[0] else None)
    worker.update.connect(update);worker.queue_progress.connect(update_queue);worker.finished_run.connect(done);worker.failed.connect(failed)
    worker.finished.connect(lambda:window.close() if closing[0] else None)
    window.show()
    # Double-click starts the selected profile without a second confirmation.
    from PySide6.QtCore import QTimer
    QTimer.singleShot(0,launch)
    return app.exec()


if __name__=='__main__':raise SystemExit(main())
