import crypto from "crypto";
import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";
import * as console from "console";

export type Node = { nodeId: number; pubKey: string};

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  let registeredNodes: GetNodeRegistryBody = { nodes: [] }; // to store registered nodes
  _registry.use(express.json());
  _registry.use(bodyParser.json());
  
  // status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  //register route
  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;
      const newNode: Node = { nodeId, pubKey };
      registeredNodes.nodes.push(newNode); // the generated key is added
      res.status(201).json({ message: "Node registered successfully" });
  });

  // node registery route
  _registry.get("/getNodeRegistry", (req, res) => {
    res.json(registeredNodes);
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
