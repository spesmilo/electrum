import unittest
from threading import Thread
from http.server import SimpleHTTPRequestHandler, HTTPServer
from ..address import Address
from ..paymentrequest import get_payment_request
from .. import paymentrequest_pb2 as pb2

class Test_PaymentRequests(unittest.TestCase):

    def setUp(self):
        self.serv = None
        self.th = None

    def tearDown(self):
        if self.serv is not None:
            self.serv.shutdown()
        if self.th is not None:
            self.th.join()

    # Verify that an error is received when an unsupported (non http/https/file) is used
    def test_get_payment_request_unsupported_scheme(self):
        pr = get_payment_request("ftp://something.com")

        self.assertTrue(pr.error is not None)

    # Verify that an error is received when we contact a non-existing server
    def test_get_payment_request_nonexistant_server(self):
        pr = get_payment_request("http://localhost:4321")

        self.assertTrue(pr.error is not None)

    # Verify that an error is received if the server does not respond with
    # 'application/bitcoincash-paymentrequest' as content type
    def test_get_paymentrequest_unsupported_contenttype(self):
        class RequestHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                resp = b"This is an invalid PaymentRequest"
                self.send_header('Content-type', 'text/plain')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

        self.serv = DummyServer(RequestHandler)
        self.th = Thread(target=self.serv.start_serve)

        self.th.start()
        pr = get_payment_request("http://localhost:1234")

        self.assertTrue(pr.error is not None)

    # Verify that an error is received if the data in the Payment Request is garbage
    def test_get_paymentrequest_invalid_payment_data(self):
        class RequestHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                resp = b'1'
                self.send_header('Content-type', 'application/bitcoincash-paymentrequest')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

        self.serv = DummyServer(RequestHandler)
        self.th = Thread(target=self.serv.start_serve)
        self.th.start()
        pr = get_payment_request("http://localhost:1234")

        self.assertTrue(pr.error is not None)

    # Verify that we get an error if the server responded with error 503
    def test_get_paymentrequest_error_503(self):
        class RequestHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                resp = b''
                self.send_response(503)
                self.send_header('Content-type', 'application/bitcoincash-paymentrequest')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

        self.serv = DummyServer(RequestHandler)
        self.th = Thread(target=self.serv.start_serve)
        self.th.start()
        pr = get_payment_request("http://localhost:1234/invoice")

        self.assertTrue(pr.error is not None)

    # Verify that a trivial payment request can be parsed and sent
    def test_get_paymentrequest_trivial_parse(self):
        class RequestHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                resp = b''
                if self.path == "/invoice":
                    pr = pb2.PaymentRequest()
                    pd = pb2.PaymentDetails()
                    pd.memo = "dummy_memo"
                    pd.time = 0
                    pd.payment_url = "http://localhost:1234/pay"
                    pd.outputs.add(amount=0, script=b'')
                    pr.serialized_payment_details = pd.SerializeToString()
                    resp = pr.SerializeToString()

                self.send_response(200)
                self.send_header('Content-type', 'application/bitcoincash-paymentrequest')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

            def do_POST(self):
                resp = b''
                if self.path == "/pay":
                    pa = pb2.PaymentACK()
                    post_data = self.rfile.read(int(self.headers['Content-Length']))
                    pa.payment.ParseFromString(post_data)
                    pa.memo = "dummy_memo_ack"
                    resp = pa.SerializeToString()

                self.send_response(200)
                self.send_header('Content-type', 'application/bitcoin-paymentack')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

        self.serv = DummyServer(RequestHandler)
        self.th = Thread(target=self.serv.start_serve)
        self.th.start()
        pr = get_payment_request("http://localhost:1234/invoice")

        self.assertTrue(pr.error is None)
        self.assertTrue(pr.get_memo() == "dummy_memo")
        self.assertTrue(pr.get_payment_url() == "http://localhost:1234/pay")

        ack, memo = pr.send_payment('010203', Address.from_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
        self.assertEqual(ack, True)
        self.assertEqual(memo, "dummy_memo_ack")

class DummyServer:
    def __init__(self, handler):
        self.httpd = HTTPServer(('localhost', 1234), handler)

    def start_serve(self):
        self.httpd.serve_forever()

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
