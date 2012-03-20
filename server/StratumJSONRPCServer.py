#!/usr/bin/env python
# Copyright(C) 2012 thomasv@gitorious

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/agpl.html>.

import jsonrpclib
from jsonrpclib import Fault
from jsonrpclib.jsonrpc import USE_UNIX_SOCKETS
import SimpleXMLRPCServer
import SocketServer
import socket
import logging
import os
import types
import traceback
import sys
try:
    import fcntl
except ImportError:
    # For Windows
    fcntl = None

import json

def get_version(request):
    # must be a dict
    if 'jsonrpc' in request.keys():
        return 2.0
    if 'id' in request.keys():
        return 1.0
    return None
    
def validate_request(request):
    if type(request) is not types.DictType:
        fault = Fault(
            -32600, 'Request must be {}, not %s.' % type(request)
        )
        return fault
    rpcid = request.get('id', None)
    version = get_version(request)
    if not version:
        fault = Fault(-32600, 'Request %s invalid.' % request, rpcid=rpcid)
        return fault        
    request.setdefault('params', [])
    method = request.get('method', None)
    params = request.get('params')
    param_types = (types.ListType, types.DictType, types.TupleType)
    if not method or type(method) not in types.StringTypes or \
        type(params) not in param_types:
        fault = Fault(
            -32600, 'Invalid request parameters or method.', rpcid=rpcid
        )
        return fault
    return True

class StratumJSONRPCDispatcher(SimpleXMLRPCServer.SimpleXMLRPCDispatcher):

    def __init__(self, encoding=None):
        SimpleXMLRPCServer.SimpleXMLRPCDispatcher.__init__(self,
                                        allow_none=True,
                                        encoding=encoding)

    def _marshaled_dispatch(self, data, dispatch_method = None):
        response = None
        try:
            request = jsonrpclib.loads(data)
        except Exception, e:
            fault = Fault(-32700, 'Request %s invalid. (%s)' % (data, e))
            response = fault.response()
            return response

        responses = []
        if type(request) is not types.ListType:
            request = [ request ]

        for req_entry in request:
            result = validate_request(req_entry)
            if type(result) is Fault:
                responses.append(result.response())
                continue
            resp_entry = self._marshaled_single_dispatch(req_entry)
            if resp_entry is not None:
                responses.append(resp_entry)

        # poll
        r = self._marshaled_single_dispatch({'method':'session.poll', 'params':[], 'id':'z' })
        r = jsonrpclib.loads(r)
        r = r.get('result')
        for item in r:
            responses.append(json.dumps(item))
            
        if len(responses) > 1:
            response = '[%s]' % ','.join(responses)
        elif len(responses) == 1:
            response = responses[0]
        else:
            response = ''

        return response

    def _marshaled_single_dispatch(self, request):
        # TODO - Use the multiprocessing and skip the response if
        # it is a notification
        # Put in support for custom dispatcher here
        # (See SimpleXMLRPCServer._marshaled_dispatch)
        method = request.get('method')
        params = request.get('params')
        if params is None: params=[]
        params = [ self.session_id, request['id'] ] + params
        #print method, params
        try:
            response = self._dispatch(method, params)
        except:
            exc_type, exc_value, exc_tb = sys.exc_info()
            fault = Fault(-32603, '%s:%s' % (exc_type, exc_value))
            return fault.response()
        if 'id' not in request.keys() or request['id'] == None:
            # It's a notification
            return None

        try:
            response = jsonrpclib.dumps(response,
                                        methodresponse=True,
                                        rpcid=request['id']
                                        )
            return response
        except:
            exc_type, exc_value, exc_tb = sys.exc_info()
            fault = Fault(-32603, '%s:%s' % (exc_type, exc_value))
            return fault.response()

    def _dispatch(self, method, params):
        func = None
        try:
            func = self.funcs[method]
        except KeyError:
            if self.instance is not None:
                if hasattr(self.instance, '_dispatch'):
                    return self.instance._dispatch(method, params)
                else:
                    try:
                        func = SimpleXMLRPCServer.resolve_dotted_attribute(
                            self.instance,
                            method,
                            True
                            )
                    except AttributeError:
                        pass
        if func is not None:
            try:
                if type(params) is types.ListType:
                    response = func(*params)
                else:
                    response = func(**params)
                return response
            except TypeError:
                return Fault(-32602, 'Invalid parameters.')
            except:
                err_lines = traceback.format_exc().splitlines()
                trace_string = '%s | %s' % (err_lines[-3], err_lines[-1])
                fault = jsonrpclib.Fault(-32603, 'Server error: %s' % 
                                         trace_string)
                return fault
        else:
            return Fault(-32601, 'Method %s not supported.' % method)

class StratumJSONRPCRequestHandler(
        SimpleXMLRPCServer.SimpleXMLRPCRequestHandler):
    
    def do_GET(self):
        if not self.is_rpc_path_valid():
            self.report_404()
            return
        try:
            self.server.session_id = None
            c = self.headers.get('cookie')
            if c:
                if c[0:8]=='SESSION=':
                    #print "found cookie", c[8:]
                    self.server.session_id = c[8:]

            if self.server.session_id is None:
                r = self.server._marshaled_single_dispatch({'method':'session.create', 'params':[], 'id':'z' })
                r = jsonrpclib.loads(r)
                self.server.session_id = r.get('result')
                #print "setting cookie", self.server.session_id

            data = json.dumps([])
            response = self.server._marshaled_dispatch(data)
            self.send_response(200)
        except Exception, e:
            self.send_response(500)
            err_lines = traceback.format_exc().splitlines()
            trace_string = '%s | %s' % (err_lines[-3], err_lines[-1])
            fault = jsonrpclib.Fault(-32603, 'Server error: %s' % trace_string)
            response = fault.response()
            print "500", trace_string
        if response == None:
            response = ''

        if hasattr(self.server, 'session_id'):
            if self.server.session_id:
                self.send_header("Set-Cookie", "SESSION=%s"%self.server.session_id)
                self.session_id = None

        self.send_header("Content-type", "application/json-rpc")
        self.send_header("Content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)
        self.wfile.flush()
        self.connection.shutdown(1)


    def do_POST(self):
        if not self.is_rpc_path_valid():
            self.report_404()
            return
        try:
            max_chunk_size = 10*1024*1024
            size_remaining = int(self.headers["content-length"])
            L = []
            while size_remaining:
                chunk_size = min(size_remaining, max_chunk_size)
                L.append(self.rfile.read(chunk_size))
                size_remaining -= len(L[-1])
            data = ''.join(L)

            self.server.session_id = None
            c = self.headers.get('cookie')
            if c:
                if c[0:8]=='SESSION=':
                    #print "found cookie", c[8:]
                    self.server.session_id = c[8:]

            if self.server.session_id is None:
                r = self.server._marshaled_single_dispatch({'method':'session.create', 'params':[], 'id':'z' })
                r = jsonrpclib.loads(r)
                self.server.session_id = r.get('result')
                #print "setting cookie", self.server.session_id

            response = self.server._marshaled_dispatch(data)
            self.send_response(200)
        except Exception, e:
            self.send_response(500)
            err_lines = traceback.format_exc().splitlines()
            trace_string = '%s | %s' % (err_lines[-3], err_lines[-1])
            fault = jsonrpclib.Fault(-32603, 'Server error: %s' % trace_string)
            response = fault.response()
            print "500", trace_string
        if response == None:
            response = ''

        if hasattr(self.server, 'session_id'):
            if self.server.session_id:
                self.send_header("Set-Cookie", "SESSION=%s"%self.server.session_id)
                self.session_id = None

        self.send_header("Content-type", "application/json-rpc")
        self.send_header("Content-length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)
        self.wfile.flush()
        self.connection.shutdown(1)


class StratumJSONRPCServer(SocketServer.TCPServer, StratumJSONRPCDispatcher):

    allow_reuse_address = True

    def __init__(self, addr, requestHandler=StratumJSONRPCRequestHandler,
                 logRequests=False, encoding=None, bind_and_activate=True,
                 address_family=socket.AF_INET):
        self.logRequests = logRequests
        StratumJSONRPCDispatcher.__init__(self, encoding)
        # TCPServer.__init__ has an extra parameter on 2.6+, so
        # check Python version and decide on how to call it
        vi = sys.version_info
        self.address_family = address_family
        if USE_UNIX_SOCKETS and address_family == socket.AF_UNIX:
            # Unix sockets can't be bound if they already exist in the
            # filesystem. The convention of e.g. X11 is to unlink
            # before binding again.
            if os.path.exists(addr): 
                try:
                    os.unlink(addr)
                except OSError:
                    logging.warning("Could not unlink socket %s", addr)
        # if python 2.5 and lower
        if vi[0] < 3 and vi[1] < 6:
            SocketServer.TCPServer.__init__(self, addr, requestHandler)
        else:
            SocketServer.TCPServer.__init__(self, addr, requestHandler,
                bind_and_activate)
        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)


