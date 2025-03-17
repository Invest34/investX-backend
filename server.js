require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const WebSocket = require("ws");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 5000;
const SALT_ROUNDS = 10;

// Ensure required environment variables exist
if (!process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_NAME) {
    console.error("❌ Database connection details are missing in environment variables");
    process.exit(1);
}

// Allow frontend to access backend
app.use(cors());
app.use(express.json());

// MySQL Connection (Using mysql2)
const db = mysql.createConnection({
    host: process.env.DB_HOST,        // Example: 'localhost' or Render's MySQL host
    user: process.env.DB_USER,        // Your MySQL username
    password: process.env.DB_PASSWORD, // Your MySQL password
    database: process.env.DB_NAME     // Your database name, e.g. 'investXpro'
});

// Connect to MySQL Database
db.connect(err => {
    if (err) {
        console.error("❌ Database connection failed:", err);
        process.exit(1);
    }
    console.log("✅ Connected to MySQL");
});

// WebSocket Server (For Login/Signup)
const wss = new WebSocket.Server({ port: 5001 });

wss.on("connection", (ws, req) => {
    const allowedOrigin = "https://investhorizon.onrender.com";
    const origin = req.headers.origin || "unknown";

    if (origin !== allowedOrigin && origin !== "unknown") {
        ws.close(403, "Forbidden");
        console.warn(`❌ WebSocket connection rejected from origin: ${origin}`);
        return;
    }
    
    console.log("✅ New WebSocket connection");

    ws.on("message", async message => {
        try {
            const data = JSON.parse(message);

            if (data.type === "signup") {
                // Check if email already exists
                db.query("SELECT * FROM users WHERE email = ?", [data.email], async (err, results) => {
                    if (err) {
                        ws.send(JSON.stringify({ status: "error", message: "Internal server error" }));
                        return;
                    }

                    if (results.length > 0) {
                        ws.send(JSON.stringify({ status: "error", message: "Email already in use" }));
                        return;
                    }

                    // Hash password
                    const hashedPassword = await bcrypt.hash(data.password, SALT_ROUNDS);
                    
                    // Insert user into database
                    db.query(
                        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                        [data.username, data.email, hashedPassword],
                        (err, result) => {
                            if (err) {
                                ws.send(JSON.stringify({ status: "error", message: "Internal server error" }));
                                return;
                            }
                            ws.send(JSON.stringify({ status: "success", message: "Signup successful" }));
                        }
                    );
                });
            }

            if (data.type === "login") {
                db.query("SELECT * FROM users WHERE email = ?", [data.email], async (err, results) => {
                    if (err) {
                        ws.send(JSON.stringify({ status: "error", message: "Database error" }));
                        return;
                    }

                    if (results.length === 0) {
                        ws.send(JSON.stringify({ status: "error", message: "Invalid email or password" }));
                        return;
                    }

                    const user = results[0];
                    const match = await bcrypt.compare(data.password, user.password_hash);

                    if (match) {
                        ws.send(JSON.stringify({ 
                            status: "success", 
                            message: "Login successful", 
                            userId: user.id, 
                            username: user.username 
                        }));
                    } else {
                        ws.send(JSON.stringify({ status: "error", message: "Invalid email or password" }));
                    }
                });
            }
        } catch (error) {
            console.error("❌ WebSocket Error:", error);
            ws.send(JSON.stringify({ status: "error", message: "Internal server error" }));
        }
    });

    ws.on("close", () => {
        console.log("🔌 WebSocket connection closed");
    });
});

// Fetch User Investments
app.get("/investments/:userId", async (req, res) => {
    const userId = req.params.userId;
    try {
        db.query("SELECT * FROM investments WHERE user_id = ?", [userId], (err, results) => {
            if (err) {
                console.error("❌ Database error:", err);
                res.status(500).json({ status: "error", message: "Database error" });
                return;
            }
            res.json({ status: "success", investments: results });
        });
    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).json({ status: "error", message: "Database error" });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
