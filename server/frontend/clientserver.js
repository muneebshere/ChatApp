const express = require("express");
const { createServer } = require("node:https");
const fs = require("fs")

const PORT = 3000;
const startApp = express();
const httpsOptions = {
  key: fs.readFileSync(`..\\certificates\\key.pem`),
  cert: fs.readFileSync(`..\\certificates\\cert.pem`)
}
startApp.use(express.static("../../client/public"));
const httpsServer = createServer(httpsOptions, startApp);
httpsServer.listen(PORT, () => console.log(`Server started on port ${PORT}`));