import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { GetNodeRegistryBody, Node } from "./../registry/registry";
import { createRandomSymmetricKey, exportSymKey, importSymKey, rsaEncrypt, symEncrypt } from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastCircuit: Node[] = [];
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.send({ "result": lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.send({ "result": lastSentMessage });
  });

  _user.get("/getLastCircuit", (req, res) => {
    res.send({ "result": lastCircuit.map(node => node.nodeId) });
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId }: SendMessageBody = req.body;
    
    try {
        // Get the registry
        const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
        const registryBody: GetNodeRegistryBody = await registryResponse.json() as GetNodeRegistryBody;
        const nodes = registryBody.nodes;

        // Create a circuit with 3 unique random nodes
        const circuit = [];
        const usedNodeIds = new Set<number>();
        while (circuit.length < 3) {
            const randomIndex = Math.floor(Math.random() * nodes.length);
            const node = nodes[randomIndex];

            if (!usedNodeIds.has(node.nodeId)) {
              circuit.push(node);
              usedNodeIds.add(node.nodeId);
            }
        }

        // Create each layer of encryption
        let encryptedMessage = message;
        let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");

        for (const node of circuit) {
            const symKey = await createRandomSymmetricKey();
            const symKeyStr = await exportSymKey(symKey);

            // (1) The previous value and the message should be concatenated and encrypted with the associated symmetric key
            const encryptedMessageLayer = await symEncrypt(symKey, destination + encryptedMessage);
            
            // Then the symmetric key needs to be encrypted with the associated node's RSA public key
            const encryptedSymKey = await rsaEncrypt(symKeyStr, node.pubKey);
            
            // Then, (2) should be concatenated with (1) in this order
            encryptedMessage = `${encryptedSymKey}${encryptedMessageLayer}`;
            destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, "0");
        }

        const finalMessage = encryptedMessage;

        // Forward the encrypted message to the entry node
        circuit.reverse();
        const entryNode = circuit[0];

        await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + entryNode.nodeId}/message`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                message: finalMessage,
            }),
        });

        lastCircuit = circuit;
        lastSentMessage = message;
        res.status(200).send("Message sent successfully");
    } catch (error) {
        console.error("Error sending message:", error);
        res.status(500).send("Failed to send message");
    }
  });

  _user.post("/message", async (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
