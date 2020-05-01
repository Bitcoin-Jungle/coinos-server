const bolt11 = require("bolt11");

module.exports = async (req, res) => {
  let hash = req.body.payreq;
  let payreq = bolt11.decode(hash);

  try {
    res.send(await lna.queryRoutes({ pub_key: payreq.payeeNodeKey, amt: payreq.satoshis }));
  } catch (e) {
    res.status(500).send(e.message);
  } 
};
