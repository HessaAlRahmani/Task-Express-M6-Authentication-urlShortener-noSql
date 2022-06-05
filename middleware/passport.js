const User = require("../models/User");
const bcrypt = require("bcrypt");
const { fromAuthHeaderAsBearerToken } = require("passport-jwt/lib/extract_jwt");
const { JWT_SECRET } = require("../config/keys");
const LocalStrategy = require("passport-local").Strategy;

const JWTStrategy = require("passport-jwt").Strategy;

exports.localStrategy = new LocalStrategy(async (username, password, done) => {
  try {
    const foundUser = await User.findOne({ username });
    const isMatch = foundUser
      ? bcrypt.compareSync(password, foundUser.password)
      : false;
    return isMatch ? done(null, foundUser) : done(null, false);
  } catch (error) {
    done(error);
  }
});

exports.jwtStrategy = new JWTStrategy(
  { jwtFromRequest: fromAuthHeaderAsBearerToken(), secretOrKey: JWT_SECRET },
  async (jwtPayload, done) => {
    if (Date.now() > jwtPayload.exp) {
      done(null, false);
    }
    try {
      const user = await User.findById(jwtPayload._id);
      if (user) {
        done(null, user);
      } else done(null, false);
    } catch (error) {
      done(error);
    }
  }
);
