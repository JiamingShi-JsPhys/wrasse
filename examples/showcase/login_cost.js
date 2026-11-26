const bcrypt = require("bcrypt");

function hash(pw) {
  return bcrypt.hash(pw, 4);
}
