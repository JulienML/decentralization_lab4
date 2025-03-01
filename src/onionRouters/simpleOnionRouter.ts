import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { exportPubKey, exportPrvKey, generateRsaKeyPair, rsaDecrypt, symDecrypt, importPrvKey } from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage : string | null = null;
  let lastReceivedDecryptedMessage : string | null = null;
  let lastMessageDestination : number | null = null;

  let rsaKeyPair = await generateRsaKeyPair();
  let publicKey = await exportPubKey(rsaKeyPair.publicKey);
  let privateKey = await exportPrvKey(rsaKeyPair.privateKey);

  onionRouter.get("/status", (req, res) => {
    res.status(200).send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.status(200).send({ "result": lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.status(200).send({ "result": lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.status(200).send({ "result": lastMessageDestination });
  });

  onionRouter.get("/getPrivateKey", (req, res) => {
    res.status(200).send({ "result": privateKey });
  });

  onionRouter.post("/message", async (req, res) => {
    const { message } = req.body;
    
    // Decrypt the message
    const decryptedKey = await rsaDecrypt(message.slice(0, 344), await importPrvKey(privateKey));
    const decryptedMessage = await symDecrypt(decryptedKey, message.slice(344));

    // Discover the next node or user
    const nextNode = parseInt(decryptedMessage.slice(0, 10), 10);
    const nextMessage = decryptedMessage.slice(10);

    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = nextMessage;
    lastMessageDestination = nextNode;

    // Transfer the message to the next node or user
    try {
      await fetch(`http://localhost:${nextNode}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: nextMessage,
        }),
      });
      res.status(200).send("Message received and forwarded.");
    } catch {
      res.status(500).send("Error while forwarding the message.");
    }
  });

  // Register the node in the registry
  try {
    await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        nodeId: nodeId,
        pubKey: publicKey,
      }),
    });
    console.log(`Node ${nodeId} registered successfully.`);
  } catch {
    console.error(`Error while registering node ${nodeId}.`);
  }

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
