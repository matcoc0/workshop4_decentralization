import crypto from "crypto"; 
import bodyParser from "body-parser"; 
import express, { Request, Response } from "express"; // for handling HTTP requests
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config"; // import configuration constants
import { exportPrvKey, exportPubKey, generateRsaKeyPair, rsaDecrypt, symDecrypt } from "../crypto"; // import implemented cryptographic functions
import { Node } from "../registry/registry"; // import Node type from registry module
import * as console from "console"; // explicitly import console module

// function to create a simple onion router
export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express(); 
  onionRouter.use(express.json()); 
  onionRouter.use(bodyParser.json()); 

  // variables so that we store the last received decrypted/encrypted messages and destination
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // generate RSA key pair for encryption/decryption
  let rsaKeyPair = await generateRsaKeyPair();
  let pubKey = await exportPubKey(rsaKeyPair.publicKey); // Export public key
  let privateKey = rsaKeyPair.privateKey; // Store private key

  // server status endpoint
  onionRouter.get("/status", (req, res) => {
    res.send("live"); // Respond with "live" status
  });

  // endpoint to get  last received encrypted message
  onionRouter.get("/getLastReceivedEncryptedMessage", (req: Request, res: Response) => {
    res.status(200).json({ result: lastReceivedEncryptedMessage });
  });

  // endpoint to get last received decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (req: Request, res: Response) => {
    res.status(200).json({ result: lastReceivedDecryptedMessage });
  });

  // endpoint to get  last message destination
  onionRouter.get("/getLastMessageDestination", (req: Request, res: Response) => {
    res.status(200).json({ result: lastMessageDestination });
  });

  // endpoint to get private key 
  onionRouter.get("/getPrivateKey", async (req, res) => {
    res.status(200).json({ result: await exportPrvKey(privateKey) }); // Export private key
  });

  // endpoint to receive and process an onion-routed message
  onionRouter.post("/message", async (req, res) => {
    const { mess } = req.body; // extract encrypted message from request body

    const decryptedKey = await rsaDecrypt(mess.slice(0, 344), privateKey); // decrypt the symmetric key using RSA private key
    
    // decrypt the actual message using the decrypted symmetric key
    const decryptedMessage = await symDecrypt(decryptedKey, mess.slice(344));

    // extract the next destination node from the decrypted message
    const nextDestination = parseInt(decryptedMessage.slice(0, 10), 10);
    const remainingMessage = decryptedMessage.slice(10); // extract the remaining message

    // update stored values for tracking and adressing potential issues
    lastReceivedEncryptedMessage = mess;
    lastReceivedDecryptedMessage = remainingMessage;
    lastMessageDestination = nextDestination;

    try {
      // forward the remaining message to the next onion router node
      await fetch(`http://localhost:${nextDestination}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ message: remainingMessage }),
      });
      res.status(200).send("success"); // responding with success
    } catch (error) {
      // @ts-ignore
      console.error("Error sending message:", error.message);
      res.status(500).json({ error: "Internal server error" }); 
    }
  });

  // register the node with the registry
  try {
    await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        nodeId: nodeId, // node Id
        pubKey: pubKey, // public key
      }),
    });
    console.log(`Node ${nodeId} registered successfully.`); // successful registration
  } catch (error) {
    // @ts-ignore
    console.error(`Error registering node ${nodeId}:`, error.message); 
  }

  // start the onion router server on the correct port
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
        `Onion router ${nodeId} is listening on port ${
            BASE_ONION_ROUTER_PORT + nodeId
        }`
    );
  });

  return server;
}
