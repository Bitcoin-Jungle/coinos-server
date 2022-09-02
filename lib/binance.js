import app from "../app.js";
import WebSocket from "ws";
import { err } from "./logging.js";
import { rates } from "./store.js";

export default () => {
  const binance = new WebSocket(
    "wss://stream.binance.com:9443/ws/btcusdt@ticker"
  );

  binance.onmessage = async function(event) {
    try {
      let msg = JSON.parse(event.data);

      let fx = app.get("fx");
      if (!fx) return;
      let rates = {};

      Object.keys(fx).map(symbol => {
        rates[symbol] = msg.c * fx[symbol];
      });

      app.set("ask", msg.a);
      app.set("bid", msg.b);
      app.set("last", msg.c);
      app.set("rates", rates);
    } catch (e) {
      err("binance message error", e.message);
    }
  };

  binance.onerror = async function(error) {
    err("binance socket error", error);
  };

  return binance;
};
