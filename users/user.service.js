const config = require("config.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const db = require("_helpers/db");
const User = db.User;

module.exports = {
  authenticate,
  logout,
  getAll,
  getById,
  create,
  update,
  delete: _delete,
  getAuditUsers,
};

async function authenticate({ username, password, role }, IP) {
  const user = await User.findOne({ username });
  if (user && bcrypt.compareSync(password, user.hash)) {
    const login_user = await User.findByIdAndUpdate(
      user._id,
      { role: role, clientIP: IP, loginTime: Date.now() },
      { new: true }
    );
    const { hash, ...userWithoutHash } = login_user.toObject();
    const token = jwt.sign({ sub: user.id }, config.secret);
    return {
      ...userWithoutHash,
      token,
    };
  }
}

async function logout({ _id }, IP) {
  return User.findByIdAndUpdate(
    _id,
    { clientIP: IP, logoutTime: Date.now() },
    { new: true }
  );
}

async function getAll() {
  return await User.find(
    {},
    { loginTime: 0, logoutTime: 0, clientIP: 0 }
  ).select("-hash");
}

async function getById(id) {
  return await User.findById(id).select("-hash");
}

async function create(userParam) {
  // validate
  if (await User.findOne({ username: userParam.username })) {
    throw 'Username "' + userParam.username + '" is already taken';
  }

  const user = new User({ ...userParam, role: "user" });

  // hash password
  if (userParam.password) {
    user.hash = bcrypt.hashSync(userParam.password, 10);
  }

  // save user
  await user.save();
}

async function update(id, userParam) {
  const user = await User.findById(id);

  // validate
  if (!user) throw "User not found";
  if (
    user.username !== userParam.username &&
    (await User.findOne({ username: userParam.username }))
  ) {
    throw 'Username "' + userParam.username + '" is already taken';
  }

  // hash password if it was entered
  if (userParam.password) {
    userParam.hash = bcrypt.hashSync(userParam.password, 10);
  }

  // copy userParam properties to user
  Object.assign(user, userParam);

  await user.save();
}

async function _delete(id) {
  await User.findByIdAndRemove(id);
}

async function getAuditUsers(id, page) {
  const { role } = await User.findById(id);
  if (role === "auditor") {
    let count = await User.find().count();
    let users = await User.find({}, {}, { skip: page * 10, limit: 10 }).select(
      "-hash"
    );
    return { users, count: count };
  }
}
