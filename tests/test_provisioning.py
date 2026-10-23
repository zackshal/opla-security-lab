"""Повторная настройка исправляет существующие элементы, сохраняя их ID."""
import importlib.util
from pathlib import Path
import unittest

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
    def test_existing_wrong_items_are_repaired_without_recreation(self):
        api = ExistingAPI()
        result = setup.provision(api, 'opla-lab-example')
        self.assertFalse(any(method.endswith('.create') for method, _ in api.calls))
        updates = {p['itemid']: p for m, p in api.calls if m == 'item.update'}
        self.assertEqual(len(updates), 11)
        self.assertEqual(result['items']['syn'], 'xdp.syn')
        self.assertEqual(updates['xdp.syn']['value_type'], 3)
        self.assertEqual(updates['xdp.syn']['type'], 2)
        self.assertEqual(updates['xdp.syn']['preprocessing'], [])
        self.assertEqual(updates['xdp.mode']['value_type'], 1)
        self.assertEqual(updates['xdp.events']['value_type'], 2)
        self.assertEqual(updates['xdp.syn.rate']['master_itemid'], 'xdp.syn')
        self.assertEqual(updates['xdp.syn.rate']['preprocessing'][0]['type'], 10)
        self.assertEqual(sum(m == 'trigger.update' for m, _ in api.calls), 5)

    def test_repeated_setup_uses_same_item_ids(self):
        api = ExistingAPI()
        a = setup.provision(api, 'opla-lab-example')
        b = setup.provision(api, 'opla-lab-example')
        self.assertEqual(a['items'], b['items'])
        self.assertEqual(a['rates'], b['rates'])
