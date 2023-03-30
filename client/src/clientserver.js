const express = require("express");
const { createServer } = require("node:https");
const fs = require("fs")

const PORT = 3000;
let counter = 0;
const max = 10;
const apps = new Map();
const httpsServers = new Map();
const targetPorts = new Map();
const startApp = express();
const httpsOptions = {
  key: fs.readFileSync(`..\\..\\certificates\\key.pem`),
  cert: fs.readFileSync(`..\\..\\certificates\\cert.pem`)
}
/* 
startApp.get("/", async (req, res, next) => {
  const { hostname } = req;
  let targetPort = targetPorts.get(hostname) ?? null;
  if (targetPort === null) {
    targetPort = PORT + ++counter;
    const newApp = express();
    const httpsServer = createServer(httpsOptions, newApp);
    targetPorts.set(hostname, targetPort);
    apps.set(hostname, newApp);
    httpsServers.set(hostname, httpsServer);
    httpsServer.listen(targetPort, () => console.log(`App started on port ${targetPort} from host ${hostname}`));
    newApp.use(express.static("../public"));
  }
  res.status(301).redirect(`https://${hostname}:${targetPort}/`);
  next();
}); */
startApp.use(express.static("../public"));
const httpsServer = createServer(httpsOptions, startApp);
httpsServer.listen(PORT, () => console.log(`Server started on port ${PORT}`));