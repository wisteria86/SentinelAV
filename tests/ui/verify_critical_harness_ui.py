# Purpose: Offscreen launcher UI check; no guests, telemetry setup or specimens.
# Works with: lab.qualification.contracts, lab.qualification.store, paths, tools.evaluation.critical_harness
# Used by: unittest discovery

"""Offscreen launcher UI check; no guests, telemetry setup or specimens."""

import os

os.environ['QT_QPA_PLATFORM']='offscreen'

from pathlib import Path

import tempfile

from unittest.mock import patch

from PySide6.QtCore import QTimer

from PySide6.QtWidgets import QApplication,QPushButton,QComboBox,QProgressBar,QLabel,QWidget

from sentinelav.paths import PROJECT_ROOT

from sentinelav.lab.qualification.contracts import CaseDefinition,SuiteManifest

from sentinelav.lab.qualification.store import RunStore

from dataclasses import asdict


def main():

    app=QApplication.instance() or QApplication([]);errors=[]

    with tempfile.TemporaryDirectory() as folder:

        root=Path(folder)

        manifest=asdict(SuiteManifest('ui','critical',{'fixture':'ui'},[asdict(CaseDefinition('ui','harness','host','selfcheck'))],{}))

        store=RunStore(root,manifest);store.start('ui');store.finish(dict(schema=1,case_id='ui',status='blocked',reason='UI fixture',observation=None));store.close()

        (root/'report.md').write_text('UI fixture only')

        class FakeRunner:

            def __init__(self,*args,**kwargs):self.progress=kwargs['queue_progress']

            def run(self):
                self.progress(0,1)
                self.progress(1,1)
                return root,dict(status='blocked')

        def verify():

            try:

                window=next(w for w in app.topLevelWidgets() if w.windowTitle()=='SentinelAV — Critical Evaluation')

                assert window.findChild(QComboBox).currentText()=='critical'

                buttons={b.text():b for b in window.findChildren(QPushButton)}

                assert buttons['Open report'].isEnabled()
                bar=window.findChild(QProgressBar)
                assert (bar.value(),bar.maximum(),bar.format())==(1,1,'1 / 1 cases recorded')
                assert any('Run ended · Blocked' in label.text() for label in window.findChildren(QLabel))

                target=PROJECT_ROOT/'artifacts/screenshots/critical-harness.png';target.parent.mkdir(parents=True,exist_ok=True)

                window.grab().save(str(target));window.close()

            except Exception as e:errors.append(str(e));app.quit()

        QTimer.singleShot(1000,verify)

        with patch('tools.evaluation.critical_harness.Runner',FakeRunner):

            from tools.evaluation.critical_harness import main as launch

            launch(['--preflight-only'])

    if errors:raise AssertionError('; '.join(errors))

    print('PASS: profile, completed state, report button and offscreen rendering; no evaluation executed.')


if __name__=='__main__':main()
