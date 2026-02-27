const jwt = require("jsonwebtoken");

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  // Expect: Authorization: Bearer <token>
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      ok: false,
      message: "Missing or invalid Authorization header",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = {
      userId: payload.userId,
      email: payload.email,
    };
    next();
  } catch (err) {
    console.error("JWT verify error:", err.message);
    return res.status(401).json({
      ok: false,
      message: "Invalid or expired token",
    });
  }
}

module.exports = requireAuth;