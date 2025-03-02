import crypto from "crypto";
import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config"; // Import port configurations
import { exportPrvKey, exportPubKey, generateRsaKeyPair, rsaDecrypt, symDecrypt } from "../crypto"; // Import cryptographic functions
import { Node } from "../registry/registry"; // Import Node type definition
import * as console from "console";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // we store the last received messages and data linked to them
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // gennerate the key pair for encryption/decryption
  let rsaKeyPair = await generateRsaKeyPair();
  let pubKey = await exportPubKey(rsaKeyPair.publicKey); // Export public key for sharing
  let privateKey = rsaKeyPair.privateKey; // Store private key for decryption

  // status route
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // last received encrypted message
  onionRouter.get("/getLastReceivedEncryptedMessage", (req: Request, res: Response) => {
    res.status(200).json({ result: lastReceivedEncryptedMessage });
  });

  // last decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (req: Request, res: Response) => {
    res.status(200).json({ result: lastReceivedDecryptedMessage });
  });

  // last known destination of a message
  onionRouter.get("/getLastMessageDestination", (req: Request, res: Response) => {
    res.status(200).json({ result: lastMessageDestination });
  });

  // retrive private key
  onionRouter.get("/getPrivateKey", async (req, res) => {
    res.status(200).json({ result: await exportPrvKey(privateKey) });
  });

  // get message
  onionRouter.post("/message", async (req, res) => {
    const { message } = req.body; // extract message

    // decrypt symmetric key using crypto function
    const decryptedKey = await rsaDecrypt(message.slice(0, 344), privateKey);

    // decrypt the  message using the decrypted key
    const decryptedMessage = await symDecrypt(decryptedKey, message.slice(344));

    // Extract the next destination from the message which has been decrypted
    const nextDestination = parseInt(decryptedMessage.slice(0, 10), 10);

    // exctract the remaining of the message
    const remainingMessage = decryptedMessage.slice(10);

    // store the received message 
    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = remainingMessage;
    lastMessageDestination = nextDestination;

    try {
      // forward the decrypted message 
      await fetch(`http://localhost:${nextDestination}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ message: remainingMessage }),
      });

      res.status(200).send("success");
    } catch (error) {
      // @ts-ignore
      console.error("Error sending message:", error.message);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // reegistering of the the onion router
  try {
    await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        nodeId: nodeId, // ID of node 
        pubKey: pubKey, // public key 
      }),
    });
    console.log(`Node ${nodeId} registered successfully.`);
  } catch (error) {
    // @ts-ignore
    console.error(`Error registering node ${nodeId}:`, error.message);
  }

  // start router
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`
    );
  });

  return server;
}
