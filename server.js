require("dotenv").config();
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");
const axios = require("axios");

// Configuration
const PORT = process.env.PORT || 3000;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID = process.env.GUILD_ID;
const ROLE_ID = process.env.ROLE_ID;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || `http://localhost:${PORT}/callback`;

// Simple JSON-based IP Store for Double Counter (Simulating DB)
const DB_FILE = path.join(__dirname, "verified_ips.json");

// Ensure DB exists
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({}));
}

const ipStore = {
    get(ip) {
        const data = JSON.parse(fs.readFileSync(DB_FILE));
        return data[ip];
    },
    set(ip, userId) {
        const data = JSON.parse(fs.readFileSync(DB_FILE));
        data[ip] = userId;
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
    }
};

// =============================================================================
// VPN DETECTION LOGIC (Inlined for Portability)
// =============================================================================
async function checkVPN(ip) {
    const apiKey = process.env.PROXYCHECK_API_KEY;

    // Basic Check if no key
    if (!apiKey) {
        const suspiciousRanges = [/^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./, /^192\.168\./, /^127\./, /^169\.254\./];
        const isSuspicious = suspiciousRanges.some(r => r.test(ip));
        return { isVPN: isSuspicious, provider: "Basic Check", country: "Unknown" };
    }

    try {
        const response = await axios.get(`https://proxycheck.io/v2/${ip}?key=${apiKey}&vpn=1&asn=1&risk=1`);
        const data = response.data[ip];
        if (!data) return { isVPN: false, provider: "Unknown", country: "Unknown" }; // Error in API response

        return {
            isVPN: data.proxy === "yes",
            provider: data.provider || "Unknown",
            country: data.country || "Unknown",
            riskScore: data.risk || 0
        };
    } catch (e) {
        console.error("VPN API Error:", e.message);
        return { isVPN: false, provider: "Error", country: "Error" }; // Fail open
    }
}
// =============================================================================

const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);

    // Serve HTML
    if (parsedUrl.pathname === "/") {
        fs.readFile(path.join(__dirname, "verification.html"), (err, data) => {
            if (err) {
                res.writeHead(500);
                res.end("Error loading page");
                return;
            }
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(data);
        });
        return;
    }

    // Callback Handler
    if (parsedUrl.pathname === "/callback") {
        const code = parsedUrl.query.code;
        const error = parsedUrl.query.error;

        if (error || !code) return redirectWithError(res, "Authorization denied.");

        try {
            // 1. Get Access Token
            if (!CLIENT_SECRET) return redirectWithError(res, "Server Config Error (No Secret)");

            // We need CLIENT_ID for the token exchange. 
            // In standalone, we MUST have it in env or we can't do the exchange easily without guessing.
            // Assumption: User provides it in .env
            const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
            if (!CLIENT_ID) return redirectWithError(res, "Server Config Error (No Client ID)");

            const tokenResponse = await axios.post("https://discord.com/api/oauth2/token", new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                code: code,
                grant_type: "authorization_code",
                redirect_uri: REDIRECT_URI,
                scope: "identify guilds.join"
            }), { headers: { "Content-Type": "application/x-www-form-urlencoded" } });

            const { access_token } = tokenResponse.data;

            // 2. Get User
            const userResponse = await axios.get("https://discord.com/api/users/@me", {
                headers: { Authorization: `Bearer ${access_token}` }
            });
            const user = userResponse.data;

            // 3. Get IP
            let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            if (ip && typeof ip === 'string') ip = ip.split(',')[0].trim();
            if (ip === '::1') ip = '127.0.0.1';

            console.log(`[Verify] User: ${user.username} (${user.id}) | IP: ${ip}`);

            // 4. VPN Check
            const vpnResult = await checkVPN(ip);
            if (vpnResult.isVPN) {
                console.log(`[Block] VPN: ${ip} (${vpnResult.provider})`);
                return redirectWithError(res, `VPN Detected! (${vpnResult.provider})`);
            }

            // 5. Anti-Alt
            const existingUser = ipStore.get(ip);
            if (existingUser && existingUser !== user.id) {
                console.log(`[Block] Alt: ${ip} linked to ${existingUser}`);
                return redirectWithError(res, "IP already used by another account.");
            }
            ipStore.set(ip, user.id);

            // 6. Grant Role (Using Bot Token)
            if (BOT_TOKEN && GUILD_ID && ROLE_ID) {
                try {
                    await axios.put(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${user.id}/roles/${ROLE_ID}`, {}, {
                        headers: { Authorization: `Bot ${BOT_TOKEN}` }
                    });
                    console.log(`[Success] Role added to ${user.username}`);
                } catch (apiError) {
                    console.error("Failed to add role:", apiError.response?.data || apiError.message);
                    // We don't fail verification if role fails (maybe they are admin or bot is below via hierarchy), 
                    // but we should probably log it.
                }
            } else {
                console.warn("Missing BOT_TOKEN, GUILD_ID, or ROLE_ID. Cannot add role.");
            }

            // Success Redirect
            res.writeHead(302, { "Location": "/?success=true" });
            res.end();

        } catch (err) {
            console.error("Verification Error:", err.message);
            redirectWithError(res, "Authentication failed.");
        }
    }
});

function redirectWithError(res, msg) {
    res.writeHead(302, { "Location": `/?error=${encodeURIComponent(msg)}` });
    res.end();
}

server.listen(PORT, () => {
    console.log(`Standalone Verification Server running on port ${PORT}`);
});
