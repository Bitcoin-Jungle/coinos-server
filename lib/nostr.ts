import config from "$config";
import { l, err } from "$lib/logging";
import { Relay, RelayPool, calculateId, signId, getPublicKey } from "nostr";
import { g, s, db } from "$lib/db";
import { fail, getInvoice, sleep, wait } from "$lib/utils";
import { nip04, nip19, finalizeEvent } from "nostr-tools";
import type { UnsignedEvent } from "nostr-tools";
import { emit } from "$lib/sockets";
import { sendInternal, sendLightning } from "$lib/payments";
import ln from "$lib/ln";
import { hex } from "@scure/base";

export const COINOS_PUBKEY = hex.encode(
  getPublicKey(nip19.decode(config.nostrKey).data),
);
export let coinos;
export let pool;

export let fillPool = () => {
  try {
    pool = RelayPool(config.relays);
    pool.on("open", (relay) => {
      if (relay.url.includes(config.nostr)) coinos = relay;
      // relay.subscribe("live", { limit: 1 });
    });

    pool.on("event", async (_, sub, ev) => {
      if (!coinos && coinos.ws.readyState !== WebSocket.OPEN) return;
      if (timeouts[sub]) timeouts[sub].extend(ev);
      try {
        let content;
        try {
          content = JSON.parse(ev.content);
        } catch (e) {
          content = ev.content;
        }

        if (sub === "live") {
          let { pubkey } = ev;

          if (Math.abs(Math.floor(Date.now() / 1000) - ev.created_at) > 7200)
            return;

          if (seen.includes(ev.id)) return;
          seen.push(ev.id);
          seen.length > 1000 && seen.shift();

          if (coinos && ev.kind < 5) {
            // coinos.send(["EVENT", ev]);
            ev.user = await getUser(pubkey);
            // broadcast("event", ev);

            if (ev.kind === 4) {
              let uid = await g(`user:${ev.tags[0][1]}`);
              if (uid) ev.recipient = await g(`user:${uid}`);
              ev.author = ev.user;
              emit(uid, "event", ev);
            }
          }
        } else if (sub.includes("profile")) {
          let { pubkey } = ev;
          let user = await getUser(pubkey);

          if (user.updated > ev.created_at) return;

          if (content.name && user.username === pubkey.substr(0, 6))
            user.username = content.name;

          delete content.name;

          user = {
            ...user,
            ...content,
            updated: ev.created_at,
          };

          await s(`user:${pubkey}`, JSON.stringify(user));
        } else if (sub.includes("messages")) {
          let pubkey = sub.split(":")[0];
          await db.sAdd(`${pubkey}:messages`, ev.id);
          await s(`ev:${ev.id}`, ev);
        } else if (sub.includes("follows")) {
          let pubkey = sub.split(":")[0];
          await s(`${pubkey}:follows`, ev.tags);
          for (let f of ev.tags) {
            let [_, followPubkey] = f;
            await db.sAdd(`${followPubkey}:followers`, pubkey);
          }
          coinos.send(ev);
        } else if (sub.includes("followers")) {
          let followed = sub.split(":")[0];
          let { pubkey } = ev;
          await db.sAdd(`${followed}:followers`, pubkey);
          coinos.send(ev);
        } else if (sub.includes("notes")) {
          let pubkey = sub.split(":")[0];
          await db.sAdd(pubkey, ev.id);
          await s(`ev:${ev.id}`, ev);
        }
      } catch (e) {
        console.log(e);
      }
    });
  } catch (e) {
    console.log("POOL", e);
  }
};

let now = () => Math.round(Date.now() / 1000);

let timeouts = {};
export let q = async (
  sub,
  query,
  { timeout = 20000, since = 3600, eager = 200 },
) =>
  new Promise(async (r, j) => {
    let start = Date.now();
    let seen = [];
    let rejected;
    // query.since = await g(`since:${sub}`);
    // if (now() - query.since < since) return r();

    let done = { [sub]: [] };

    let check = (s) => {
      let elapsed = Date.now() - start;
      if (rejected) return true;
      if (
        done[s] &&
        (done[s].length === pool.relays.length ||
          (done[s].length && elapsed > eager))
      ) {
        r();
        if (timeouts[s]) timeouts[s].clear();
        return true;
      }
    };

    timeouts[sub] = {
      async clear() {
        clearTimeout(this.timer);
        delete timeouts[sub];
        pool.unsubscribe(sub);
        await s(`since:${sub}`, now());
      },
      extend(ev) {
        if (ev) {
          if (seen.includes(ev.id)) return;
          seen.push(ev.id);
          seen.length > 1000 && seen.shift();
        }

        clearTimeout(this.timer);
        this.timer = setTimeout(() => {
          j(new Error(`query timed out: ${sub} ${Date.now()}`));
          pool.unsubscribe(sub);
          rejected = true;
        }, timeout);
      },
      timer: undefined,
    };

    timeouts[sub].extend();
    pool.subscribe(sub, query);

    pool.on("eose", (relay, s) => {
      if (done[s]) done[s].push(relay.url);
      check(s);
    });

    try {
      await wait(() => check(sub), 100, 200);
    } catch (e) {
      console.log(e);
    }
  });

let seen = [];

let getUser = async (pubkey) => {
  let id = await g(`user:${pubkey}`);
  let user = await g(`user:${id}`);
  return (
    user || {
      username: pubkey.substr(0, 6),
      pubkey,
      anon: true,
    }
  );
};

function send(ev, url, opts) {
  let timeout = (opts && opts.timeout != null && opts.timeout) || 1000;

  return new Promise((resolve, reject) => {
    let relay = Relay(url);

    function timeout_reached() {
      relay.close();
      reject(new Error("Request timeout"));
    }

    let timer = setTimeout(timeout_reached, timeout);

    relay.on("open", () => {
      clearTimeout(timer);
      timer = setTimeout(timeout_reached, timeout);
      relay.send(["EVENT", ev]);
    });

    relay.on("ok", (evid, ok, msg) => {
      clearTimeout(timer);
      relay.close();
      resolve({ evid, ok, msg });
    });
  });
}

export async function handleZap(invoice) {
  let { data: privkey } = nip19.decode(config.nostrKey);
  let pubkey = getPublicKey(privkey);
  let keypair = { privkey, pubkey };
  let zapreq = JSON.parse(invoice.description);

  if (!zapreq.tags || zapreq.tags.length === 0) {
    fail(`No tags found`);
  }

  let ptags = zapreq.tags.filter(
    (t) => t && t.length && t.length >= 2 && t[0] === "p",
  );

  if (ptags.length !== 1) {
    fail(`None or multiple p tags found`);
  }

  let etags = zapreq.tags.filter(
    (t) => t && t.length && t.length >= 2 && t[0] === "e",
  );

  if (!(etags.length === 0 || etags.length === 1)) {
    fail(`Expected none or 1 e tags`);
  }

  let relays_tag = zapreq.tags.find(
    (t) => t && t.length && t.length >= 2 && t[0] === "relays",
  );

  if (!relays_tag) {
    fail(`No relays tag found`);
  }

  let relays = relays_tag.slice(1).filter((r) => r && r.startsWith("ws"));
  let etag = etags.length > 0 && etags[0];
  let ptag = ptags[0];

  let kind = 9735;
  let created_at = invoice.paid_at;
  let content = zapreq.content;

  let tags = [ptag];
  if (etag) tags.push(etag);

  tags.push(["bolt11", invoice.bolt11]);
  tags.push(["description", invoice.description]);
  tags.push(["preimage", invoice.payment_preimage]);

  let ev = { pubkey, kind, created_at, content, tags };
  ev.id = await calculateId(ev);
  ev.sig = await signId(privkey, ev.id);

  l("sending receipt");

  await Promise.allSettled(relays.map((r) => send(ev, r)));
}

let r = new Relay("ws://strfry:7777");
r.on("open", (_) => {
  r.subscribe("nwc", { kinds: [23194], "#p": [COINOS_PUBKEY] });
});

r.on("event", async (sub, ev) => {
  try {
    if (sub !== "nwc") return;
    let { content, pubkey } = ev;
    let sk = nip19.decode(config.nostrKey).data as Uint8Array;
    let { params, method } = JSON.parse(
      await nip04.decrypt(sk, pubkey, content),
    );

    let uid = await g(pubkey);
    let user = await g(`user:${uid}`);

    let ret = { result_type: method, result: undefined, error: undefined };

    if (method === "pay_invoice") {
      let { invoice: pr } = params;
      let { amount_msat, payee } = await ln.decode(pr);
      let { id } = await ln.getinfo();
      let amount = Math.round(amount_msat / 1000);

      if (payee === id) {
        let invoice = await getInvoice(pr);
        let recipient = await g(`user:${invoice.uid}`);

        await sendInternal({
          amount,
          invoice,
          recipient,
          sender: user,
        });

        ret.result = { preimage: recipient.id};
      } else {
        await sendLightning({
          amount,
          user,
          pr,
          maxfee: 50,
        });

        for (let i = 0; i < 10; i++) {
          let { pays } = await ln.listpays(pr);
          let p = pays.find((p) => p.status === "complete");
          if (p) {
            let { preimage } = p;
            ret.result = { preimage };
            break;
          }
          await sleep(2000);
        }

        if (!ret.result)
          ret.error = { code: "INTERNAL", message: "Payment timed out" };
      }
    } else if (method === "get_info") {
      let { alias, blockheight, color } = await ln.getinfo();
      ret.result = {
        alias,
        color,
        pubkey: COINOS_PUBKEY,
        network: "mainnet",
        block_height: blockheight,
        methods: ["pay_invoice", "get_balance", "get_info"],
      };
    } else if (method === "get_balance") {
      ret.result = {
        balance: await g(`balance:${uid}`),
      };
    }

    content = await nip04.encrypt(sk, pubkey, JSON.stringify(ret));

    let response: UnsignedEvent = {
      created_at: Math.floor(Date.now() / 1000),
      kind: 23195,
      pubkey: COINOS_PUBKEY,
      tags: [
        ["p", pubkey],
        ["e", ev.id],
      ],
      content,
    };

    response = await finalizeEvent(response, sk);
    r.send(["EVENT", response]);
  } catch (e) {
    err("problem with nwc", e.message);
  }
});
