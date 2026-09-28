const http = require("http");
const port = process.env.PORT || 8080;
http.createServer((req, res) => {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("hello from node " + (process.env.GREETING || "") + "\n");
}).listen(port, "0.0.0.0");
