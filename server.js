require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const WebSocket = require("ws");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 5000;
const SALT_ROUNDS = 10;

// Allow frontend to access backend
app.use(cors());
app.use(express.json());

// PostgreSQL Connection (Neon Database)
const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for Neon PostgreSQL
});

db.connect()
    .then(() => console.log("✅ Connected to PostgreSQL"))
    .catch(err => console.error("❌ Database connection failed:", err));

// WebSocket Server (For Login/Signup)
const wss = new WebSocket.Server({ port: 5001 });

wss.on("connection", ws => {
    console.log("New WebSocket connection");

    ws.on("message", async message => {
        const data = JSON.parse(message);
        
        if (data.type === "signup") {
            try {
                // Check if email already exists
                const emailCheck = await db.query("SELECT * FROM users WHERE email = $1", [data.email]);
                if (emailCheck.rows.length > 0) {
                    ws.send(JSON.stringify({ status: "error", message: "Email already in use" }));
                    return;
                }

                // Hash password
                const hashedPassword = await bcrypt.hash(data.password, SALT_ROUNDS);
                
                // Insert user into database
                await db.query(
                    "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
                    [data.username, data.email, hashedPassword]
                );

                ws.send(JSON.stringify({ status: "success", message: "Signup successful" }));
            } catch (error) {
                ws.send(JSON.stringify({ status: "error", message: "Internal server error" }));
            }
        }

        if (data.type === "login") {
            try {
                const userQuery = await db.query("SELECT * FROM users WHERE email = $1", [data.email]);
                if (userQuery.rows.length === 0) {
                    ws.send(JSON.stringify({ status: "error", message: "Invalid email or password" }));
                    return;
                }

                const user = userQuery.rows[0];
                const match = await bcrypt.compare(data.password, user.password_hash);

                if (match) {
                    ws.send(JSON.stringify({ status: "success", message: "Login successful", userId: user.id, username: user.username }));
                } else {
                    ws.send(JSON.stringify({ status: "error", message: "Invalid email or password" }));
                }
            } catch (error) {
                ws.send(JSON.stringify({ status: "error", message: "Database error" }));
            }
        }
    });
});

// Fetch User Investments
app.get("/investments/:userId", async (req, res) => {
    const userId = req.params.userId;
    try {
        const investments = await db.query("SELECT * FROM investments WHERE user_id = $1", [userId]);
        res.json({ status: "success", investments: investments.rows });
    } catch (err) {
        res.status(500).json({ status: "error", message: "Database error" });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
