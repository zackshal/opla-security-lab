import subprocess
import unittest
from unittest.mock import patch

from tests.test_opla_unified_cli import cli


class InteractiveCreateTests(unittest.TestCase):
    def test_user_authenticates_in_original_terminal_without_make(self):
        with patch.object(cli.os, 'geteuid', return_value=1000), patch.object(cli.subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0)
            self.assertEqual(cli.main(['lab', 'create', '--confirm-host-changes']), 0)
            run.assert_called_once_with(
                ['sudo', 'python3', str(cli.ROOT / 'bin/opla-create-launcher.py')], check=False)

    def test_root_does_not_reenter_sudo(self):
        with patch.object(cli.os, 'geteuid', return_value=0), patch.object(cli.subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 2)
            self.assertEqual(cli.main(['lab', 'create', '--confirm-host-changes']), 2)
            self.assertEqual(run.call_args.args[0][0], 'python3')

    def test_missing_confirmation_never_prompts_or_executes(self):
        with patch.object(cli.subprocess, 'run') as run:
            self.assertEqual(cli.main(['lab', 'create']), 2)
            run.assert_not_called()
