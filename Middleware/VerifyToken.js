const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "No token provided. Unauthorized",
    });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, "bazmaSecretKey", (err, user) => {
    if (err) {
      return res.status(403).json({
        message: "Invalid token. Forbidden",
      });
    }
    req.user = user;
    return next();
  });
};

module.exports = verifyToken;