const jwt = require("jsonwebtoken");

const authenticateToken = async(req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    // Check for missing token
    if (!token) {
        return res.status(401).json({ message: "Unauthorized: No valid access token" });
    }

    // Validate the environment variable
    if (!process.env.ACCESS_TOKEN_SECRET) {
        console.error("ACCESS_TOKEN_SECRET is not defined in the environment variables.");
        return res.status(500).json({ message: "Server configuration error." });
    }

    try {
        // Verify the access token
        const decodedAccess = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        // Attach user info to the request object
        req.user = decodedAccess;
        // Proceed to the next middleware or route handler
        return next();
    } catch (error) {
        console.error("Access token verification failed:", error.message);

        // Forbidden response for invalid token
        return res.status(403).json({ message: "Forbidden: Invalid or expired token" });
    }
};

module.exports = authenticateToken;