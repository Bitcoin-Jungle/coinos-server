export default async (req, res) => {
  let address = await bc.getNewAddress();
  await bc.generateToAddress(1, address);
  res.send({});
};
