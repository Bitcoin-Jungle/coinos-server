import app from "$app";
import { auth, optional } from "$lib/auth";
import { getLocations } from "$lib/locations";
import { getRates, sendRates } from "$lib/rates";
import { sendHeartbeat } from "$lib/sockets";

import email from "$routes/email";
import locations from "$routes/locations";
import nostr from "$routes/nostr";
import rates from "$routes/rates";
import invoices from "$routes/invoices";
import users from "$routes/users";
import payments from "$routes/payments";
import requests from "$routes/requests";

getLocations();
getRates();

setInterval(sendRates, 1000);
setInterval(sendHeartbeat, 2000);

app.post("/email", email.send);

app.get("/rate", rates.last);
app.get("/rates", rates.index);

app.get("/nostr.json", nostr.identities);
app.get("/:pubkey/followers", nostr.followers);
app.get("/:pubkey/follows", nostr.follows);
app.get("/:pubkey/notes", nostr.notes);
app.get("/event/:id", nostr.event);
app.post("/event", nostr.broadcast);

app.get("/locations", locations.list);

app.get("/invoice", invoices.get);
app.post("/invoice", optional, invoices.create);

app.post("/send", auth, payments.send);
app.get("/payments", auth, payments.list);
app.get("/payments/:hash", auth, payments.get);
app.post("/lightning/send", auth, payments.sendLightning);

app.get("/voucher/:id", payments.voucher);
app.post("/redeem", optional, payments.redeem);

app.get("/me", auth, users.me);
app.get("/users/:key", users.get);
app.post("/register", users.create);
app.post("/disable2fa", users.disable2fa);
app.post("/2fa", auth, users.enable2fa);
app.post("/user", auth, users.update);
app.post("/upload/:type", auth, users.upload);

app.post("/login", users.login);
app.post("/logout", optional, users.logout);

app.post("/subscribe", auth, users.subscribe);
app.post("/password", auth, users.password);
app.post("/otpsecret", auth, users.otpsecret);
app.get("/contacts", auth, users.contacts);

app.get("/request/:id", auth, requests.get);
app.get("/requests", auth, requests.list);
app.post("/requests", auth, requests.create);
app.post("/requests/delete", auth, requests.destroy);

let host = process.env.HOST || "0.0.0.0";
let port = process.env.PORT || 3119;

app.listen({ host, port });
