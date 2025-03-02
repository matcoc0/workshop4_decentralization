import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import {GetNodeRegistryBody, Node} from "@/src/registry/registry";
import {createRandomSymmetricKey, exportSymKey, importSymKey, rsaEncrypt, symEncrypt} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

let lastCircuit: Node[] = [];
let lastReceivedMessage: string | null = null;
let lastSentMessage: string | null = null;

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.get("/getLastCircuit", (req, res) => {
    res.status(200).json({result: lastCircuit.map((node) => node.nodeId)});
  });

  _user.post("/message", (req, res) => {
    const { message }: { message: string } = req.body;

    if (message) {
      lastReceivedMessage = message;
      res.status(200).send("success");
    } else {
      res.status(400).json({ error: "Invalid request body" });
    }
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId }: { message: string; destinationUserId: number } = req.body;

    // Fetch the node registry to get information about registered nodes
    try {
      const response = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const data = await response.json();
      // @ts-ignore
      const nodes: Node[] = data.nodes;

      // Pick 3 random distinct nodes from the registry
      const selectedNodes: Node[] = getRandomDistinctNodes(nodes, 3);

      // Encrypt the message with layers of encryption and forward to entry node
      const encryptedMessage = await encryptAndForwardMessage(message, destinationUserId, selectedNodes);

      selectedNodes.reverse()

      // Forward the encrypted message to the entry node
      await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + selectedNodes[0].nodeId}/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message: encryptedMessage })
      });

      lastSentMessage = message; // Update last sent message
      lastCircuit = selectedNodes; // Update last circuit

      res.status(200).json({ message: "Message sent successfully" });
    } catch (error) {
      // @ts-ignore
      console.error("Error sending message:", error.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}

function getRandomDistinctNodes(nodes: any[], count: number): any[] {
  const result: any[] = [];
  const indexes = new Set();

  while (result.length < count && indexes.size < nodes.length) {
    const index = Math.floor(Math.random() * nodes.length);
    if (!indexes.has(index)) {
      indexes.add(index);
      result.push(nodes[index]);
    }
  }

  return result;
}

async function encryptAndForwardMessage(message: string, destinationUserId: number, nodes: any[]): Promise<string> {
  let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");
  let finalMessage = message;

  for(const node of nodes) {
    const symmetricKey = await createRandomSymmetricKey();
    const symmetricKey64 = await exportSymKey(symmetricKey);
    const encryptedMessage = await symEncrypt(symmetricKey, `${destination + finalMessage}`);
    destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, '0');
    const encryptedSymKey = await rsaEncrypt(symmetricKey64, node.pubKey);
    finalMessage = encryptedSymKey + encryptedMessage;
  }

  return finalMessage;
}
