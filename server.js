require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
const rateLimit = require("express-rate-limit");

const app = express();

app.use(express.json());
app.use(express.static("public"));

// 🌐 ROOT ROUTE
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PASSWORD_HASH = process.env.PASSWORD_HASH;

// 📅 DOCUMENT EXPIRY DATA
const documentStatus = {
    insurance: "2026-07-21",
    license: "2032-06-12",
    rc: "2035-07-27"
};

// 🔐 FILE ID MAP
const fileMap = {
    "1": "rc.pdf",
    "2": "insurance.pdf",
    "3": "license.pdf"
};

// 📁 CREATE LOGS FOLDER
const logDir = path.join(__dirname, "logs");

if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// 📄 LOG FILE PATH
const logFilePath = path.join(logDir, "access.log");

// 📊 LOGGER (FIXED)
const logAccess = (req, action) => {
    let ip =
        req.headers["x-forwarded-for"] ||
        req.socket.remoteAddress ||
        req.ip;

    if (ip === "::1") ip = "LOCALHOST";
    if (ip.includes("::ffff:")) ip = ip.split("::ffff:")[1];

    const time = new Date().toISOString();
    const device = req.headers["user-agent"];

    const log = `${time} | ${ip} | ${action} | ${device}\n`;

    fs.appendFile(logFilePath, log, (err) => {
        if (err) console.error("Log error:", err);
    });
};

// 🚫 RATE LIMIT
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 5,
    message: { message: "Too many attempts. Try again after 5 minutes." }
});

// 🔐 LOGIN
app.post("/api/login", loginLimiter, async (req, res) => {
    const { password } = req.body;

    if (!password) {
        logAccess(req, "LOGIN FAILED - NO PASSWORD");
        return res.status(400).json({ message: "Password required" });
    }

    const match = await bcrypt.compare(password, PASSWORD_HASH);

    if (!match) {
        logAccess(req, "LOGIN FAILED");
        return res.status(401).json({ message: "Invalid password" });
    }

    logAccess(req, "LOGIN SUCCESS");

    const token = jwt.sign(
        { user: "bike_owner" },
        process.env.JWT_SECRET,
        { expiresIn: "10m" }
    );

    res.json({ token });
});

// 🔐 TOKEN CHECK
function verifyToken(req, res, next) {
    const token = req.headers["authorization"];

    if (!token) return res.status(403).json({ message: "No token" });

    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}

// 📄 DOC ACCESS
app.get("/api/docs/:id", verifyToken, (req, res) => {
    const file = fileMap[req.params.id];

    if (!file) return res.status(404).send("Invalid document");

    logAccess(req, `DOC ACCESS - ${file}`);

    const filePath = path.join(__dirname, "docs", file);

    if (!fs.existsSync(filePath)) {
        return res.status(404).send("File not found");
    }

    res.sendFile(filePath);
});

// 📊 LOG DASHBOARD (FIXED PATH)
app.get("/api/logs", verifyToken, (req, res) => {
    if (!fs.existsSync(logFilePath)) return res.json([]);

    const data = fs.readFileSync(logFilePath, "utf-8");

    const logs = data.trim().split("\n").map(line => {
        const [time, ip, action, device] = line.split(" | ");
        return { time, ip, action, device };
    });

    const failCount = {};

    logs.forEach(log => {
        if (log.action.includes("FAILED")) {
            failCount[log.ip] = (failCount[log.ip] || 0) + 1;
        }
    });

    logs.forEach(log => {
        log.suspicious = failCount[log.ip] >= 3;
    });

    res.json(logs.reverse());
});

// 📅 EXPIRY API
app.get("/api/status", (req, res) => {
    res.json(documentStatus);
});

// 🚀 START SERVER
app.listen(process.env.PORT, "0.0.0.0", () => {
    console.log("🚀 Server running on port " + process.env.PORT);
});
