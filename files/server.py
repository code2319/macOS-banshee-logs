import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class RequestLoggerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"Received GET request to {self.path}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"GET request logged.")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        body = post_data.decode('utf-8', errors='ignore')
        
        print(f"Received POST request to {self.path}")
        print(f"Headers: {self.headers}")
        print(f"Body: {body}")

        try:
            parts = body.split(":")
            if len(parts) > 2:
                filename = parts[-1].strip('"}') + ".json"
                key = parts[-2].strip()
                print(f"\nExtracted original filename: {filename.strip('.json')}.zip")
                print(f"Extracted key: {key}")

                with open("server-files/" + filename, "w") as file:
                    json.dump(json.loads(body), file)
                print(f"Data written to {filename}")
        except Exception as e:
            print(f"An error occured while processing the body: {e}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"POST request logged.")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8000), RequestLoggerHandler)
    print("Starting HTTP server on port 8000...")
    server.serve_forever()
