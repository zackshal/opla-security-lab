#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import yaml

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('suricata_validate',ROOT/'security/suricata/manage.py')
manager=importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    for mode in ['ids','ips']:
        config=manager.config(mode,'100.64.0.0/29',False)
        config['default-rule-path']=str(ROOT/'security/suricata')
        config['default-log-dir']=str(root)
        path=root/(mode+'.yaml')
        path.write_text(yaml.safe_dump(config))
        subprocess.run(['suricata','-T','-c',str(path)],check=True)
