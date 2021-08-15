const express = require("express");
const router = express.Router();
const userService = require("./user.service");

// routes
router.post("/authenticate", authenticate);
router.post("/logout", logout);
router.post("/register", register);
router.get("/", getAll);
router.get("/audit/:id", getAuditUsers);
router.get("/current", getCurrent);
router.get("/:id", getById);
router.put("/:id", update);
router.delete("/:id", _delete);

module.exports = router;

function authenticate(req, res, next) {
  userService
    .authenticate(req.body, req.ip)
    .then((user) =>
      user
        ? res.json(user)
        : res.status(400).json({ message: "Username or password is incorrect" })
    )
    .catch((err) => next(err));
}

function logout(req, res, next) {
  userService
    .logout(req.body, req.ip)
    .then((response) =>
      response
        ? res.status(200).json({ message: "logout successfull" })
        : res.status(400).json({ message: " logout failed" })
    )
    .catch((err) => next(err));
}

function register(req, res, next) {
  userService
    .create(req.body)
    .then(() => res.json({}))
    .catch((err) => next(err));
}

function getAll(req, res, next) {
  userService
    .getAll()
    .then((users) => res.json(users))
    .catch((err) => next(err));
}

function getCurrent(req, res, next) {
  userService
    .getById(req.user.sub)
    .then((user) => (user ? res.json(user) : res.sendStatus(404)))
    .catch((err) => next(err));
}

function getById(req, res, next) {
  userService
    .getById(req.params.id)
    .then((user) => (user ? res.json(user) : res.sendStatus(404)))
    .catch((err) => next(err));
}

function update(req, res, next) {
  userService
    .update(req.params.id, req.body)
    .then(() => res.json({}))
    .catch((err) => next(err));
}

function _delete(req, res, next) {
  userService
    .delete(req.params.id)
    .then(() => res.json({}))
    .catch((err) => next(err));
}

function getAuditUsers(req, res, next) {
  userService
    .getAuditUsers(req.params.id, req.get("page"))
    .then((response) =>
      response
        ? res.json(response)
        : res.status(401).json({ message: "unauthorised request" })
    )
    .catch((err) => next(err));
}
