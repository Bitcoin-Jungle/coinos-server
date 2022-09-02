import sequelize from 'sequelize';
const { Op } = sequelize;

getUser = async (username, transaction) => {
  let params = {
    include: [
      {
        model: db.Account,
        as: "account",
      },
    ],
    where: {
      username: { [Op.or]: [username, username.replace(/ /g, "")] },
    },
  };

  if (transaction) {
    params.lock = transaction.LOCK.UPDATE;
    params.transaction = transaction;
  }

  let user = await db.User.findOne(params);
  if (!user) throw new Error(`User ${username} not found`);

  return user;
};

getUserById = async (id, transaction) => {
  let params = {
    include: [
      {
        model: db.Account,
        as: "account",
      },
    ],
    where: { id },
  };

  if (transaction) {
    params.lock = transaction.LOCK.UPDATE;
    params.transaction = transaction;
  }

  let user = await db.User.findOne(params);
  if (!user) throw new Error("User not found");

  return user;
};
