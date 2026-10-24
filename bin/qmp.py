#!/usr/bin/env python3
import json
import socket
import time

class QMP:
    def __init__(self, path, timeout=120):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile('rwb')
        self.timeout = timeout
        self.sequence = 0
        greeting = self._read()
        if 'QMP' not in greeting:
            self.close()
            raise RuntimeError('Invalid QMP greeting')
        self.call('qmp_capabilities')

    def _read(self):
        raw = self.stream.readline(1024 * 1024 + 1)
        if not raw or len(raw) > 1024 * 1024:
            raise RuntimeError('QMP disconnected or response too large')
        return json.loads(raw)

    def call(self, command, arguments=None):
        self.sequence += 1
        request = {'execute': command, 'id': self.sequence}
        if arguments is not None:
            request['arguments'] = arguments
        self.stream.write(json.dumps(request).encode() + b'\r\n')
        self.stream.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('QMP command deadline')
            self.socket.settimeout(remaining)
            answer = self._read()
            if 'event' in answer:
                continue
            if answer.get('id') != self.sequence:
                raise RuntimeError('QMP response ID mismatch')
            if 'error' in answer:
                raise RuntimeError(str(answer['error']))
            if 'return' not in answer:
                raise RuntimeError('QMP response without return')
            return answer['return']

    def hmp(self, command):
        return self.call('human-monitor-command', {'command-line': command})

    def close(self):
        self.stream.close()
        self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
