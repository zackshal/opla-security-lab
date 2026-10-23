import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'xdp'))
sys.path.insert(0,str(ROOT/'monitoring'))
import collect
import bridge
class MonitoringTests(unittest.TestCase):
    def test_large_byte_counter(self):
        n=2**42+1027
        self.assertEqual(collect.number([hex(b) for b in n.to_bytes(8,sys.byteorder)]),n)
    def test_per_cpu_aggregation(self):
        replies=[ [{'xdp':{'attached':'generic','prog':{'id':4}}}],
                  {'id':4},
                  [{'key':['0x02','0x00','0x00','0x00'],'values':[
                    {'cpu':0,'value':300},{'cpu':1,'value':['0x01','0x01','0x00','0x00','0x00','0x00','0x00','0x00']}]}]]
        with patch.object(collect,'run',side_effect=replies):
            self.assertEqual(collect.snapshot()['drop'],557)
    def test_detached_is_not_native(self):
        with patch.object(collect,'run',return_value=[{}]):
            self.assertEqual(collect.snapshot()['loaded'],0)
    def test_wrong_program_rejected(self):
        with patch.object(collect,'run',side_effect=[[{'xdp':{'attached':'drv','prog':{'id':9}}}],{'id':4}]):
            with self.assertRaises(ValueError): collect.snapshot()
    def exchange(self,reply):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        got=[]
        def server():
            with listener:
                conn,_=listener.accept()
                with conn:
                    h=bridge.recv_exact(conn,13)
                    got.append(json.loads(bridge.recv_exact(conn,struct.unpack('<Q',h[5:])[0])))
                    body=json.dumps(reply).encode()
                    frame=b'ZBXD\x01'+struct.pack('<Q',len(body))+body
                    # TCP has no message boundaries: deliberately fragment the response.
                    for b in frame: conn.sendall(bytes([b]))
        thread=threading.Thread(target=server);thread.start()
        try:
            result=bridge.send([{'host':'test','key':'xdp.loaded','value':'1'}],port=listener.getsockname()[1])
            self.assertEqual(got[0]['request'],'sender data')
            return result
        finally:thread.join(timeout=5)
    def test_sender_framing(self):
        self.exchange({'response':'success','info':'processed: 1; failed: 0; total: 1; seconds spent: 0.1'})
    def test_sender_partial_failure(self):
        with self.assertRaises(ValueError):
            self.exchange({'response':'success','info':'processed: 0; failed: 1; total: 1; seconds spent: 0.1'})
