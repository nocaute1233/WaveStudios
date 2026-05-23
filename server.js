require("dotenv").config();
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");
const axios = require("axios");

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID = process.env.GUILD_ID;
const ROLE_ID = process.env.ROLE_ID;
const UNVERIFIED_ROLE_ID = process.env.UNVERIFIED_ROLE_ID;
const LOGS_CHANNEL_ID = process.env.LOGS_CHANNEL_ID;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || `http://localhost:${PORT}/callback`;
const MIN_ACCOUNT_DAYS = Number(process.env.MIN_ACCOUNT_DAYS || 3);

const requiredEnvVars = {
    DISCORD_CLIENT_ID: CLIENT_ID,
    DISCORD_CLIENT_SECRET: CLIENT_SECRET,
    DISCORD_BOT_TOKEN: BOT_TOKEN,
    GUILD_ID: GUILD_ID,
    ROLE_ID: ROLE_ID
};

const missingVars = Object.entries(requiredEnvVars)
    .filter(([, value]) => !value)
    .map(([key]) => key);

if (missingVars.length > 0) {
    console.error("\n❌ Variáveis em falta no .env:");
    missingVars.forEach((v) => console.error(`   - ${v}`));
    process.exit(1);
}

const DB_FILE = path.join(__dirname, "verified_ips.json");
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({}));
}

const rateLimit = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 20;

function applySecurityHeaders(res) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' https://cdn.discordapp.com data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    );
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
}

function checkRateLimit(ip) {
    const now = Date.now();
    const entry = rateLimit.get(ip) || { count: 0, start: now };
    if (now - entry.start > RATE_WINDOW_MS) {
        entry.count = 0;
        entry.start = now;
    }
    entry.count += 1;
    rateLimit.set(ip, entry);
    return entry.count <= RATE_MAX;
}

const ipStore = {
    get(ip) {
        const data = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
        return data[ip];
    },
    set(ip, userId) {
        const data = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
        data[ip] = userId;
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
    }
};

function getClientIp(req) {
    let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    if (ip && typeof ip === "string") ip = ip.split(",")[0].trim();
    if (ip === "::1") ip = "127.0.0.1";
    return ip;
}

function redirectWithError(res, msg, extra = {}) {
    const q = new URLSearchParams({ error: msg, ...extra }).toString();
    res.writeHead(302, { Location: `/?${q}` });
    res.end();
}

async function sendLog(embed) {
    if (!LOGS_CHANNEL_ID) return;
    try {
        await axios.post(
            `https://discord.com/api/v10/channels/${LOGS_CHANNEL_ID}/messages`,
            { embeds: [embed] },
            { headers: { Authorization: `Bot ${BOT_TOKEN}` } }
        );
    } catch (e) {
        console.error("[Log]", e.response?.data || e.message);
    }
}

const server = http.createServer(async (req, res) => {
    applySecurityHeaders(res);
    const clientIp = getClientIp(req);

    if (!checkRateLimit(clientIp)) {
        res.writeHead(429, { "Content-Type": "text/plain" });
        res.end("Too many requests");
        return;
    }

    const parsedUrl = url.parse(req.url, true);

    if (parsedUrl.pathname === "/" || parsedUrl.pathname === "/verify") {
        const htmlPath = path.join(__dirname, "verification.html");
        fs.readFile(htmlPath, (err, data) => {
            if (err) {
                res.writeHead(500);
                res.end("Erro ao carregar página");
                return;
            }
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
            res.end(data);
        });
        return;
    }

    if (parsedUrl.pathname === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
    }

    if (parsedUrl.pathname === "/callback") {
        const code = parsedUrl.query.code;
        const error = parsedUrl.query.error;

        if (error || !code) {
            return redirectWithError(res, "Autorização cancelada.");
        }

        try {
            const tokenResponse = await axios.post(
                "https://discord.com/api/oauth2/token",
                new URLSearchParams({
                    client_id: CLIENT_ID,
                    client_secret: CLIENT_SECRET,
                    code,
                    grant_type: "authorization_code",
                    redirect_uri: REDIRECT_URI,
                    scope: "identify guilds.join"
                }),
                { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
            );

            const { access_token } = tokenResponse.data;
            const userResponse = await axios.get("https://discord.com/api/users/@me", {
                headers: { Authorization: `Bearer ${access_token}` }
            });
            const user = userResponse.data;

            const avatarUrl = user.avatar
                ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
                : `https://cdn.discordapp.com/embed/avatars/${Number(user.discriminator || 0) % 5}.png`;

            const ip = clientIp;
            const fail = (msg) => redirectWithError(res, msg, {
                username: user.username,
                avatar: avatarUrl,
                userid: user.id
            });

            const accountAgeDays = (Date.now() - snowflakeToDate(user.id)) / (86400000);
            if (accountAgeDays < MIN_ACCOUNT_DAYS) {
                await sendLog({
                    title: "Verificação recusada • Conta recente",
                    color: 0x2563eb,
                    thumbnail: { url: avatarUrl },
                    fields: [
                        { name: "Utilizador", value: `${user.username} (\`${user.id}\`)`, inline: true },
                        { name: "Idade", value: `~${accountAgeDays.toFixed(1)} dias`, inline: true }
                    ],
                    footer: { text: "Wave Studios • Verificação" },
                    timestamp: new Date().toISOString()
                });
                return fail(`A tua conta precisa de ter pelo menos ${MIN_ACCOUNT_DAYS} dias.`);
            }

            const existingUser = ipStore.get(ip);
            if (existingUser && existingUser !== user.id) {
                await sendLog({
                    title: "Anti-Alt • Rede já associada",
                    color: 0x2563eb,
                    thumbnail: { url: avatarUrl },
                    fields: [
                        { name: "Utilizador", value: `${user.username} (\`${user.id}\`)`, inline: true },
                        { name: "Conta ligada", value: `\`${existingUser}\``, inline: true }
                    ],
                    footer: { text: "Wave Studios • Verificação" },
                    timestamp: new Date().toISOString()
                });
                return fail("Esta rede já está associada a outra conta Discord.");
            }

            ipStore.set(ip, user.id);

            if (GUILD_ID && ROLE_ID) {
                await axios.put(
                    `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${user.id}/roles/${ROLE_ID}`,
                    {},
                    { headers: { Authorization: `Bot ${BOT_TOKEN}` } }
                );

                if (UNVERIFIED_ROLE_ID) {
                    await axios.delete(
                        `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${user.id}/roles/${UNVERIFIED_ROLE_ID}`,
                        { headers: { Authorization: `Bot ${BOT_TOKEN}` } }
                    ).catch(() => {});
                }

                await sendLog({
                    title: "Verificação concluída",
                    color: 0x2563eb,
                    thumbnail: { url: avatarUrl },
                    fields: [
                        { name: "Utilizador", value: `${user.username} (\`${user.id}\`)`, inline: true },
                        { name: "Estado", value: "Cargo atribuído", inline: true }
                    ],
                    footer: { text: "Wave Studios • Verificação" },
                    timestamp: new Date().toISOString()
                });
            }

            const successQuery = new URLSearchParams({
                success: "true",
                username: user.username,
                avatar: avatarUrl
            }).toString();
            res.writeHead(302, { Location: `/?${successQuery}` });
            res.end();
        } catch (err) {
            console.error("[Callback]", err.response?.data || err.message);
            redirectWithError(res, "Falha na autenticação. Tenta novamente.");
        }
        return;
    }

    res.writeHead(404);
    res.end("Not found");
});

/** Estima data de criação da conta a partir do snowflake Discord */
function snowflakeToDate(id) {
    const DISCORD_EPOCH = 1420070400000;
    return Number((BigInt(id) >> 22n) + BigInt(DISCORD_EPOCH));
}

server.listen(PORT, () => {
    console.log(`Verificação Wave Studios • porta ${PORT}`);
});
