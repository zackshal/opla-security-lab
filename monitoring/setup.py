#!/usr/bin/env python3
"""Создаём узел, items, триггеры, графики и dashboard через Zabbix 7.0 API."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import urllib.request
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'bin'))
sys.path.insert(0,str(R/'monitoring'))
from state import load

class API:
    def __init__(self,url): self.url=url;self.auth=None
    def call(self,method,params):
        body={'jsonrpc':'2.0','id':1,'method':method,'params':params}
        if self.auth: body['auth']=self.auth
        req=urllib.request.Request(self.url,json.dumps(body).encode(),{'Content-Type':'application/json-rpc'})
        with urllib.request.urlopen(req,timeout=15) as response: data=json.load(response)
        if 'error' in data:raise RuntimeError(str(data['error']))
        return data['result']

def field(name,value,kind=0):return {'type':kind,'name':name,'value':str(value)}

def upsert_item(api, hid, params):
    found = api.call('item.get', {'hostids': [hid], 'filter': {'key_': [params['key_']]}})
    if found:
        itemid = found[0]['itemid']
        update = {k: v for k, v in params.items() if k != 'hostid'}
        api.call('item.update', dict(update, itemid=itemid))
        return itemid
    return api.call('item.create', params)['itemids'][0]


def policy_settings():
    p = json.loads((R/'monitoring/policy.json').read_text())
    import re
    for key in ['event_hold', 'collector_timeout']:
        if not re.fullmatch(r'[1-9][0-9]*[smh]', p[key]):
            raise ValueError('Некорректный интервал ' + key)
    for key in ['syn_peak_pps', 'drop_peak_pps']:
        if type(p[key]) is not int or p[key] < 1:
            raise ValueError('Некорректный порог ' + key)
    return p


def provision(api, name):
    from catalog import DEFINITIONS, BY_NAME, RATES, item_key
    policy = policy_settings()
    groups = api.call('hostgroup.get', {'filter': {'name': ['OPLA Lab']}})
    gid = groups[0]['groupid'] if groups else api.call('hostgroup.create', {'name': 'OPLA Lab'})['groupids'][0]
    hosts = api.call('host.get', {'filter': {'host': [name]}})
    hid = hosts[0]['hostid'] if hosts else api.call('host.create', {'host': name, 'groups': [{'groupid': gid}]})['hostids'][0]
    api.call('host.update', {'hostid': hid, 'status': 0})
    ids = {}
    labels = {}
    for key, wire, label, kind, units in DEFINITIONS:
        params = {'hostid': hid, 'name': label, 'key_': wire, 'type': 2,
                  'value_type': kind, 'delay': '0', 'history': '7d', 'status': 0,
                  'trends': '30d' if kind == 3 else '0', 'units': units,
                  'trapper_hosts': '', 'preprocessing': [],
                  'tags': [{'tag': 'component', 'value': wire.split('.')[0]}]}
        ids[key] = upsert_item(api, hid, params)
        labels[key] = label
    rates = {}
    for key in RATES:
        wire = item_key(key) + '.rate'
        units = 'Bps' if key == 'rx_bytes' else ('rps' if key.startswith('http_') else 'pps')
        label = BY_NAME[key][2] + ' / s'
        rates[key] = upsert_item(api, hid, {
            'hostid': hid, 'name': label, 'key_': wire, 'type': 18,
            'value_type': 0, 'master_itemid': ids[key], 'units': units,
            'history': '7d', 'trends': '30d', 'status': 0,
            'tags': [{'tag': 'component', 'value': wire.split('.')[0]}],
            'preprocessing': [{'type': 10, 'params': '', 'error_handler': 1, 'error_handler_params': ''}]})
        labels[key+'.rate'] = label
    hold = policy['event_hold']
    descriptions = [
        ('Suricata configured but down', f'last(/{name}/ids.enabled)=1 and last(/{name}/ids.up)=0', 4, 'ids'),
        ('Suricata alert observed', f'max(/{name}/ids.alerts.rate,{hold})>0', 2, 'ids'),
        ('Suricata blocked traffic', f'max(/{name}/ids.blocked.rate,{hold})>0', 3, 'ids'),
        ('Suricata capture drops', f'max(/{name}/ids.kernel_drops.rate,{hold})>0', 3, 'ids'),
        ('EVE parse errors', f'change(/{name}/ids.parse_errors)>0', 2, 'ids'),
        ('XDP is detached', f'last(/{name}/xdp.loaded)=0', 3, 'xdp'),
        ('SYN packets are being dropped', f'max(/{name}/xdp.drop.rate,{hold})>0', 2, 'xdp'),
        ('Collector has no data', f'nodata(/{name}/xdp.loaded,{policy["collector_timeout"]})=1', 3, 'collector'),
        ('SYN map capacity reached', f'max(/{name}/xdp.map_full.rate,{hold})>0', 3, 'xdp'),
        ('Fragmented TCP packets dropped', f'max(/{name}/xdp.fragment_drop.rate,{hold})>0', 2, 'xdp'),
        ('High SYN pressure with drops', f'max(/{name}/xdp.syn.rate,{hold})>{policy["syn_peak_pps"]} and max(/{name}/xdp.drop.rate,{hold})>{policy["drop_peak_pps"]}', 3, 'xdp'),
        ('HTTP telemetry unavailable', f'last(/{name}/http.available)=0', 2, 'http'),
        ('HTTP requests rate limited', f'max(/{name}/http.limited.rate,{hold})>0', 2, 'http'),
        ('HTTP server errors observed', f'max(/{name}/http.errors5xx.rate,{hold})>0', 3, 'http'),
        ('HTTP telemetry parse errors', f'change(/{name}/http.parse_errors)>0', 2, 'collector'),
        ('HTTP local probe failed', f'max(/{name}/http.up,#3)=0', 3, 'http'),
        ('HTTP local probe is slow', f'min(/{name}/http.latency,#3)>500000', 2, 'http')]
    for desc, expression, severity, component in descriptions:
        found = api.call('trigger.get', {'hostids': [hid], 'filter': {'description': [desc]}})
        params = {'description': desc, 'expression': expression, 'priority': severity, 'status': 0,
                  'tags': [{'tag': 'component', 'value': component}, {'tag': 'lab', 'value': name}]}
        if found:
            api.call('trigger.update', dict(params, triggerid=found[0]['triggerid']))
        else:
            api.call('trigger.create', params)
    def graph(title, metrics):
        found = api.call('graph.get', {'hostids': [hid], 'filter': {'name': [title]}})
        params = {'name': title, 'width': 900, 'height': 260,
                  'gitems': [{'itemid': item, 'color': ['1976D2', '388E3C', 'D32F2F'][i % 3], 'sortorder': i}
                             for i, item in enumerate(metrics)]}
        if found:
            graphid = found[0]['graphid']
            api.call('graph.update', dict(params, graphid=graphid))
            return graphid
        return api.call('graph.create', params)['graphids'][0]
    graphs = [graph('SYN packets per second', [rates[k] for k in ['syn', 'pass', 'drop']]),
              graph('SYN cumulative counters', [ids[k] for k in ['syn', 'pass', 'drop']]),
              graph('HTTP requests per second', [rates[k] for k in ['http_requests', 'http_limited', 'http_5xx']]),
              graph('Interface receive packets', [rates['rx_packets']]),
              graph('Interface receive bytes', [rates['rx_bytes']])]
    references = iter(range(10000))
    def tiles(keys):
        widgets = []
        for index, key in enumerate(keys):
            rate = key.endswith('.rate')
            item = rates[key[:-5]] if rate else ids[key]
            widgets.append({'type': 'item', 'name': labels[key],
                            'x': (index % 4)*18, 'y': (index//4)*3, 'width': 18, 'height': 3,
                            'fields': [field('itemid.0', item, 4), field('rf_rate', 10),
                                       field('reference', 'I'+str(next(references)).zfill(4), 1)]})
        return widgets, ((len(keys)+3)//4)*3
    def chart(graphid, x, y, ref):
        return {'type': 'graph', 'x': x, 'y': y, 'width': 36, 'height': 5,
                'fields': [field('source_type', 0), field('graphid.0', graphid, 6),
                           field('reference', ref, 1), field('rf_rate', 10)]}
    xdp, y = tiles(['loaded', 'mode', 'syn', 'pass', 'drop', 'map_full', 'fragment_drop',
                    'syn.rate', 'pass.rate', 'drop.rate', 'map_full.rate', 'fragment_drop.rate'])
    xdp.extend([chart(graphs[0], 0, y, 'SYNAA'), chart(graphs[1], 36, y, 'SYNAB')])
    xdp.append({'type': 'itemhistory', 'name': 'Security events (XDP and HTTP)',
                'x': 0, 'y': y+5, 'width': 72, 'height': 5,
                'fields': [field('columns.0.itemid', ids['events'], 4), field('columns.0.name', 'Event', 1),
                           field('columns.0.monospace_font', 1), field('show_timestamp', 1),
                           field('reference', 'LOGAA', 1), field('show_lines', 20), field('rf_rate', 10)]})
    xdp.append({'type': 'problems', 'name': 'Recent problems for this lab',
                'x': 0, 'y': y+10, 'width': 72, 'height': 5,
                'fields': [field('hostids.0', hid, 3), field('show', 2), field('show_lines', 20),
                           field('rf_rate', 10), field('reference', 'PRBAA', 1)]})
    http, y = tiles(['http_up', 'http_status', 'http_latency_us', 'http_available',
                     'http_requests', 'http_limited', 'http_5xx', 'http_parse_errors',
                     'http_requests.rate', 'http_limited.rate', 'http_5xx.rate'])
    http.append(chart(graphs[2], 0, y, 'HTTPA'))
    network, y = tiles(['rx_packets', 'rx_bytes', 'rx_packets.rate', 'rx_bytes.rate'])
    network.extend([chart(graphs[3], 0, y, 'NETAA'), chart(graphs[4], 36, y, 'NETAB')])
    sensor, y = tiles(['ids_enabled', 'ids_up', 'ids_alerts', 'ids_blocked',
                       'ids_parse_errors', 'ids_kernel_drops', 'ids_alerts.rate',
                       'ids_blocked.rate', 'ids_kernel_drops.rate'])
    title = 'OPLA / ' + name
    existing = api.call('dashboard.get', {'filter': {'name': [title]}})
    params = {'name': title, 'pages': [{'name': 'XDP and events', 'widgets': xdp},
                                      {'name': 'HTTP protection', 'widgets': http},
                                      {'name': 'Interface traffic', 'widgets': network},
                                      {'name': 'IDS and IPS', 'widgets': sensor}]}
    if existing:
        api.call('dashboard.update', dict(params, dashboardid=existing[0]['dashboardid']))
    else:
        api.call('dashboard.create', params)
    return {'host': name, 'hostid': hid, 'items': ids, 'rates': rates, 'dashboard': params, 'policy': policy}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--lab',required=True);args=parser.parse_args()
    d=load(args.lab)
    api=API('http://127.0.0.1:8080/api_jsonrpc.php')
    version=api.call('apiinfo.version',{})
    if not version.startswith('7.0.'):sys.exit('Ожидается Zabbix 7.0.x, получен '+version)
    username=input('Zabbix user [Admin]: ').strip() or 'Admin'
    password=getpass.getpass('Zabbix password: ')
    api.auth=api.call('user.login',{'username':username,'password':password})
    try:
        result=provision(api,'opla-'+d['LAB_ID'])
        out=R/'monitoring/runtime'/d['LAB_ID'];out.mkdir(parents=True,exist_ok=True)
        (out/'provisioned.json').write_text(json.dumps(result,indent=2))
        print(f'Настроены {len(result["items"])+len(result["rates"])} элементов, 17 триггеров и dashboard из 4 страниц.')
        print('Сбор данных: make monitoring-start')
    finally:api.call('user.logout',[])
