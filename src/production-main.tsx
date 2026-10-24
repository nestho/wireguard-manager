import React from "react";
import { createRoot } from "react-dom/client";
import ProductionApp from "./ProductionApp";
import "./production.css";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode><ProductionApp /></React.StrictMode>
);
