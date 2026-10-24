import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import ProductionApp from "./ProductionApp";
import "./styles.css";
import "./production.css";

const isProductionApp = import.meta.env.VITE_APP_MODE === "production";
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>{isProductionApp ? <ProductionApp /> : <App />}</React.StrictMode>
);
