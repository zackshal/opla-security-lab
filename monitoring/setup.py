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

def provision(api,name):
    groups=api.call('hostgroup.get',{'filter':{'name':['OPLA Lab']}})
    gid=groups[0]['groupid'] if groups else api.call('hostgroup.create',{'name':'OPLA Lab'})['groupids'][0]
    hosts=api.call('host.get',{'filter':{'host':[name]}})
    hid=hosts[0]['hostid'] if hosts else api.call('host.create',{'host':name,'groups':[{'groupid':gid}]})['hostids'][0]
    api.call('host.update',{'hostid':hid,'status':0})
    definitions=[('loaded','XDP attached',3),('syn','SYN total',3),('pass','SYN passed',3),
                 ('drop','SYN dropped',3),('map_full','Map capacity drops',3),
                 ('fragment_drop','Fragment drops',3),('mode','XDP mode',1),('events','XDP interval log',2)]
    ids={}
    for key,label,kind in definitions:
        found=api.call('item.get',{'hostids':[hid],'filter':{'key_':['xdp.'+key]}})
        params={'hostid':hid,'name':label,'key_':'xdp.'+key,'type':2,'value_type':kind,'delay':'0',
                'history':'7d','status':0,'trapper_hosts':'','preprocessing':[],
                'tags':[{'tag':'component','value':'xdp'}]}
        params['trends']='30d' if kind==3 else '0'
        if found:
            ids[key]=found[0]['itemid']
            update={k:v for k,v in params.items() if k!='hostid'}
            update['itemid']=ids[key]
            api.call('item.update',update)
        else:
            ids[key]=api.call('item.create',params)['itemids'][0]
    rates={}
    for key in ['syn','pass','drop']:
        k='xdp.'+key+'.rate'
        found=api.call('item.get',{'hostids':[hid],'filter':{'key_':[k]}})
        params={
            'hostid':hid,'name':key+' packets/s','key_':k,'type':18,'value_type':0,
            'master_itemid':ids[key],'units':'pps','history':'7d','trends':'30d',
            'status':0,'tags':[{'tag':'component','value':'xdp'}],
            'preprocessing':[{'type':10,'params':'','error_handler':1,'error_handler_params':''}]}
        if found:
            rates[key]=found[0]['itemid']
            update={k:v for k,v in params.items() if k!='hostid'}
            update['itemid']=rates[key]
            api.call('item.update',update)
        else:
            rates[key]=api.call('item.create',params)['itemids'][0]
    descriptions=[('XDP is detached',f'last(/{name}/xdp.loaded)=0',3),
        ('SYN packets are being dropped',f'last(/{name}/xdp.drop.rate)>0',2),
        ('Collector has no data',f'nodata(/{name}/xdp.loaded,30s)=1',3),
        ('SYN map capacity reached',f'change(/{name}/xdp.map_full)>0',3),
        ('Fragmented TCP packets dropped',f'change(/{name}/xdp.fragment_drop)>0',2)]
    for desc,expr,priority in descriptions:
        found=api.call('trigger.get',{'hostids':[hid],'filter':{'description':[desc]}})
        params={'description':desc,'expression':expr,'priority':priority,'status':0,
                'tags':[{'tag':'component','value':'xdp'}]}
        if found:
            params['triggerid']=found[0]['triggerid'];api.call('trigger.update',params)
        else:api.call('trigger.create',params)
    graphs=[]
    for title,items in [('SYN packets per second',rates),('SYN cumulative counters',{k:ids[k] for k in ['syn','pass','drop']})]:
        found=api.call('graph.get',{'hostids':[hid],'filter':{'name':[title]}})
        graph=found[0]['graphid'] if found else api.call('graph.create',{'name':title,'width':900,'height':260,
            'gitems':[{'itemid':i,'color':c,'sortorder':j} for j,((_,i),c) in enumerate(zip(items.items(),['1976D2','388E3C','D32F2F']))]})['graphids'][0]
        graphs.append(graph)
    widgets=[]
    for index,graph in enumerate(graphs):
        widgets.append({'type':'graph','name':['SYN / s','Cumulative SYN'][index],
            'x':index*36,'y':0,'width':36,'height':5,
            'fields':[field('source_type',0),field('graphid.0',graph,6),field('reference','GRAA'+str(index),1),field('rf_rate',10)]})
    widgets.append({'type':'itemhistory','name':'XDP events','x':0,'y':5,'width':72,'height':5,
        'fields':[field('columns.0.itemid',ids['events'],4),field('columns.0.name','Events',1),field('columns.0.monospace_font',1),field('show_timestamp',1),field('reference','LOGAA',1),field('show_lines',20),field('rf_rate',10)]})
    widgets.append({'type':'item','name':'XDP attached','x':0,'y':10,'width':24,'height':3,
        'fields':[field('itemid.0',ids['loaded'],4),field('rf_rate',10)]})
    for index,key in enumerate(['map_full','fragment_drop']):
        widgets.append({'type':'item','name':key,'x':(index+1)*24,'y':10,'width':24,'height':3,
            'fields':[field('itemid.0',ids[key],4),field('rf_rate',10)]})
    title='OPLA / '+name
    existing=api.call('dashboard.get',{'filter':{'name':[title]}})
    params={'name':title,'pages':[{'name':'XDP overview','widgets':widgets}]}
    if existing:params['dashboardid']=existing[0]['dashboardid'];api.call('dashboard.update',params)
    else:api.call('dashboard.create',params)
    return {'host':name,'hostid':hid,'items':ids,'rates':rates,'dashboard':params}

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
        print('Узел и dashboard созданы. Сбор данных: make monitoring-start')
    finally:api.call('user.logout',[])
