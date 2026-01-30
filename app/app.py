from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "0.0.0.0"
PORT = 8000

class AppHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Hello, this is the AppSec CI/CD lab")

if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), AppHandler)
    print(f"Starting server on {HOST}:{PORT}")
    server.serve_forever()
