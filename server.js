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

const UNVERIFIED_ROLE_ID = process.env.UNVERIFIED_ROLE_ID;
const LOGS_CHANNEL_ID = process.env.LOGS_CHANNEL_ID;

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
            if (!CLIENT_SECRET || !BOT_TOKEN) return redirectWithError(res, "Server Config Error (Check .env)");

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
            const avatarUrl = user.avatar
                ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
                : `https://cdn.discordapp.com/embed/avatars/${user.discriminator % 5}.png`;

            // 3. Get IP
            let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            if (ip && typeof ip === 'string') ip = ip.split(',')[0].trim();
            if (ip === '::1') ip = '127.0.0.1';

            console.log(`[Verify] User: ${user.username} (${user.id}) | IP: ${ip}`);

            // Helper to Redirect with Avatar
            const fail = (msg) => {
                const q = new URLSearchParams({
                    error: msg,
                    username: user.username,
                    avatar: avatarUrl,
                    userid: user.id
                }).toString();
                res.writeHead(302, { "Location": `/?${q}` });
                res.end();
            };

            // 4. VPN Check
            const vpnResult = await checkVPN(ip);
            if (vpnResult.isVPN) {
                console.log(`[Block] VPN: ${ip} (${vpnResult.provider})`);

                // DM User
                try {
                    const ch = await axios.post(`https://discord.com/api/v10/users/@me/channels`, { recipient_id: user.id }, { headers: { Authorization: `Bot ${BOT_TOKEN}` } });
                    await axios.post(`https://discord.com/api/v10/channels/${ch.data.id}/messages`, {
                        content: `⚠️ **Security Alert**\nHi ${user.username}, our system detected a VPN/Proxy connection (${vpnResult.provider}).\nPlease turn off your VPN or use your main network to verify.`
                    }, { headers: { Authorization: `Bot ${BOT_TOKEN}` } });
                } catch (e) { console.error("Failed to DM user:", e.message); }

                // Log to Discord Channel
                if (LOGS_CHANNEL_ID) {
                    try {
                        await axios.post(`https://discord.com/api/v10/channels/${LOGS_CHANNEL_ID}/messages`, {
                            embeds: [{
                                title: "🛡️ VPN Detected (Web Verify)",
                                color: 0xFF0000,
                                thumbnail: { url: avatarUrl },
                                fields: [
                                    { name: "User", value: `${user.username} (${user.id})`, inline: true },
                                    { name: "IP", value: `||${ip}||`, inline: true },
                                    { name: "Provider", value: vpnResult.provider, inline: true },
                                    { name: "Country", value: vpnResult.country, inline: true }
                                ]
                            }]
                        }, { headers: { Authorization: `Bot ${BOT_TOKEN}` } });
                    } catch (e) { console.error("Failed to log:", e.message); }
                }

                return fail(`VPN Detected! (${vpnResult.provider}). Please disable it.`);
            }

            // 5. Anti-Alt
            const existingUser = ipStore.get(ip);
            if (existingUser && existingUser !== user.id) {
                console.log(`[Block] Alt: ${ip} linked to ${existingUser}`);
                return fail("This network is already associated with another account.");
            }
            ipStore.set(ip, user.id);

            // 6. Manage Roles (Grant Verified, Remove Unverified)
            if (GUILD_ID && ROLE_ID) {
                try {
                    // Give Verified Role
                    await axios.put(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${user.id}/roles/${ROLE_ID}`, {}, {
                        headers: { Authorization: `Bot ${BOT_TOKEN}` }
                    });

                    // Remove Unverified Role
                    if (UNVERIFIED_ROLE_ID) {
                        await axios.delete(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${user.id}/roles/${UNVERIFIED_ROLE_ID}`, {
                            headers: { Authorization: `Bot ${BOT_TOKEN}` }
                        }).catch(e => console.error("Failed to remove unverified role:", e.message));
                    }

                    console.log(`[Success] Verified ${user.username}`);
                } catch (apiError) {
                    console.error("Failed to add role:", apiError.response?.data || apiError.message);
                }
            }

            // Success Redirect
            const s = new URLSearchParams({ success: "true", username: user.username, avatar: avatarUrl }).toString();
            res.writeHead(302, { "Location": `/?${s}` });
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
