"""Повторная настройка исправляет существующие элементы, сохраняя их ID."""
import importlib.util
from pathlib import Path
import unittest
import io
import urllib.error
from unittest.mock import patch, Mock

path = Path(__file__).resolve().parents[1] / 'monitoring/setup.py'
spec = importlib.util.spec_from_file_location('opla_setup', path)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class ExistingAPI:
    def __init__(self):
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        responses = {
            'hostgroup.get': [{'groupid': '1'}],
            'host.get': [{'hostid': '2'}],
            'trigger.get': [{'triggerid': '3'}],
            'graph.get': [{'graphid': '4'}],
            'dashboard.get': [{'dashboardid': '5'}],
        }
        if method == 'item.get':
            return [{'itemid': params['filter']['key_'][0]}]
        return responses.get(method, {})


class ProvisioningTests(unittest.TestCase):
    def test_unsafe_local_runtime_blocks_authenticated_api_writes(self):
        with patch.object(setup, 'load', return_value={'LAB_ID': 'lab-Ab12'}), \
             patch.object(setup.API, 'wait_ready', return_value='7.0.19'), \
             patch('builtins.input', return_value='Admin'), \
             patch.object(setup.getpass, 'getpass', return_value='not-a-real-password'), \
             patch.object(setup, 'prepare_runtime', side_effect=ValueError('unsafe local runtime')), \
             patch.object(setup.API, 'call') as call:
            with self.assertRaisesRegex(ValueError, 'unsafe local runtime'):
                setup.main(['--lab', '/tmp/lab-Ab12'])
            call.assert_not_called()

    def test_api_response_is_bounded(self):
        api = setup.API('http://127.0.0.1:8080/api_jsonrpc.php')
        with patch.object(api.opener, 'open', return_value=io.BytesIO(b'x' * (setup.MAX_API_RESPONSE+1))):
            with self.assertRaisesRegex(ValueError, '1 MiB'):
                api.call('apiinfo.version', {})

    def test_invalid_version_fails_before_credentials_or_provisioning(self):
        with patch.object(setup, 'load', return_value={'LAB_ID': 'lab-Ab12'}), \
             patch.object(setup.API, 'wait_ready', return_value=None), \
             patch('builtins.input') as prompt:
            with self.assertRaisesRegex(RuntimeError, 'некорректную версию'):
                setup.main(['--lab', '/tmp/lab-Ab12'])
            prompt.assert_not_called()

    def test_api_wait_retries_only_read_only_probe_until_ready(self):
        api = setup.API('http://127.0.0.1:8080/api_jsonrpc.php')
        clock = [0]
        def sleep(seconds):
            clock[0] += seconds
        with patch.object(api, 'call', side_effect=[setup.APIUnavailable('503'), '7.0.19']) as call:
            self.assertEqual(api.wait_ready(clock=lambda: clock[0], sleep=sleep), '7.0.19')
        self.assertEqual([c.args[0] for c in call.call_args_list], ['apiinfo.version', 'apiinfo.version'])

    def test_api_wait_has_finite_deadline(self):
        api = setup.API('http://127.0.0.1:8080/api_jsonrpc.php')
        clock = [0]
        with patch.object(api, 'call', side_effect=setup.APIUnavailable('503')) as call:
            with self.assertRaisesRegex(setup.APIUnavailable, 'не готов'):
                api.wait_ready(timeout=3, clock=lambda: clock[0],
                               sleep=lambda seconds: clock.__setitem__(0, clock[0]+seconds))
        self.assertEqual(call.call_count, 2)

    def test_api_does_not_retry_mutation_or_follow_proxy_environment(self):
        with patch.object(setup.urllib.request, 'build_opener') as build:
            api = setup.API('http://127.0.0.1:8080/api_jsonrpc.php')
        self.assertEqual(build.call_args.args[0].proxies, {})
        api.opener.open.side_effect = urllib.error.HTTPError(api.url, 503, 'unavailable', {}, io.BytesIO())
        with self.assertRaises(setup.APIUnavailable):
            api.call('host.create', {})
        api.opener.open.assert_called_once()

    def test_existing_wrong_items_are_repaired_without_recreation(self):
        api = ExistingAPI()
        result = setup.provision(api, 'opla-lab-example')
        self.assertFalse(any(method.endswith('.create') for method, _ in api.calls))
        updates = {p['itemid']: p for m, p in api.calls if m == 'item.update'}
        self.assertEqual(len(updates), 50)
        self.assertEqual(result['items']['syn'], 'xdp.syn')
        self.assertEqual(updates['xdp.syn']['value_type'], 3)
        self.assertEqual(updates['xdp.syn']['type'], 2)
        self.assertEqual(updates['xdp.syn']['preprocessing'], [])
        self.assertEqual(updates['xdp.mode']['value_type'], 1)
        self.assertEqual(updates['xdp.events']['value_type'], 2)
        self.assertEqual(updates['xdp.syn.rate']['master_itemid'], 'xdp.syn')
        self.assertEqual(updates['xdp.syn.rate']['preprocessing'][0]['type'], 10)
        self.assertEqual(sum(m == 'trigger.update' for m, _ in api.calls), 23)

    def test_repeated_setup_uses_same_item_ids(self):
        api = ExistingAPI()
        a = setup.provision(api, 'opla-lab-example')
        b = setup.provision(api, 'opla-lab-example')
        self.assertEqual(a['items'], b['items'])
        self.assertEqual(a['rates'], b['rates'])

    def test_dashboard_covers_every_item_without_overlapping_tiles(self):
        api = ExistingAPI()
        result = setup.provision(api, 'opla-lab-example')
        dashboard = result['dashboard']
        self.assertEqual(len(dashboard['pages']), 5)
        expected = set(result['items'].values()) | set(result['rates'].values())
        shown = {f['value'] for page in dashboard['pages'] for widget in page['widgets']
                 for f in widget.get('fields', []) if f['type'] == 4}
        self.assertTrue(expected <= shown, expected-shown)
        for page in dashboard['pages']:
            widgets = page['widgets']
            for i, a in enumerate(widgets):
                self.assertLessEqual(a['x']+a['width'], 72)
                for b in widgets[i+1:]:
                    overlap = (a['x'] < b['x']+b['width'] and b['x'] < a['x']+a['width'] and
                               a['y'] < b['y']+b['height'] and b['y'] < a['y']+a['height'])
                    self.assertFalse(overlap, (page['name'], a, b))

    def test_http_metrics_have_correct_wire_keys_and_rates(self):
        api = ExistingAPI()
        setup.provision(api, 'opla-lab-example')
        updates = {p['itemid']: p for m, p in api.calls if m == 'item.update'}
        self.assertEqual(updates['http.limited']['type'], 2)
        self.assertEqual(updates['http.limited.rate']['master_itemid'], 'http.limited')
        triggers = [p for m, p in api.calls if m == 'trigger.update']
        self.assertTrue(any('http.limited.rate,30s' in t['expression'] for t in triggers))

    def test_widget_references_are_unique(self):
        result = setup.provision(ExistingAPI(), 'opla-lab-example')
        references = [f['value'] for page in result['dashboard']['pages'] for widget in page['widgets']
                      for f in widget['fields'] if f['name'] == 'reference']
        self.assertEqual(len(references), len(set(references)))
        self.assertTrue(all(len(ref) == 5 for ref in references))

    def test_fresh_setup_creates_complete_catalog_and_dashboard(self):
        class NewAPI:
            def __init__(self):
                self.calls = []
            def call(self, method, params):
                self.calls.append((method, params))
                if method.endswith('.get'):
                    return []
                if method.endswith('.create'):
                    prefix = method.split('.')[0]
                    field = 'groupids' if prefix == 'hostgroup' else prefix+'ids'
                    return {field: [str(len(self.calls))]}
                return {}
        api = NewAPI()
        result = setup.provision(api, 'opla-lab-example')
        self.assertEqual(sum(m == 'item.create' for m, _ in api.calls), 50)
        self.assertEqual(sum(m == 'trigger.create' for m, _ in api.calls), 23)
        self.assertEqual(sum(m == 'graph.create' for m, _ in api.calls), 5)
        self.assertEqual(len(result['dashboard']['pages']), 5)
