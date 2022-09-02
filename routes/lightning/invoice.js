
export default ah(async (req, res) => {
  let { amount, memo, tip } = req.body;
  if (!tip) tip = 0;
  let value = amount + tip;

  try {
    if (config.lna.clightning) {
      if (!memo) memo = "coinos";
      const invoice = await lna.invoice(
        value ? `${value}sat` : "any",
        new Date(),
        memo,
        360
      );
      res.send({ text: invoice.bolt11 });
    } else {
      const invoice = await lnp.addInvoice({ value, memo });
      res.send({ text: invoice.payment_request });
    }
  } catch (e) {
    l.error("problem creating invoice", e.message, e.stack);
    res.status(500).send(e.message);
  }
});
