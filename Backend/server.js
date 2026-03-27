const express = require("express");
const crypto = require("crypto");
const db = require("./conexionbd");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

// Inicializar llaves RSA para la encriptacion hibrida
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// AES key
const AES_KEY = crypto.createHash('sha256').update(String("clave_secreta_luis_aes")).digest();

app.get("/public-key", (req, res) => {
    res.json({ publicKey: publicKey.toString('pem') });
});

app.post("/texto", async (req, res) => {
    try {
        const { texto } = req.body;
        if (!texto) return res.status(400).json({ error: "Intentalo otra vez, mandaste el texto vacio" });

        const hash = crypto.createHash('sha256').update(texto).digest('hex');

        db.query("INSERT INTO textos (texto_hash) VALUES (?)", [hash], (err) => {
            if (err) return res.status(500).json({ error: "DB Error" });
            res.json({ mensaje: "Texto hasheado: ", hash });
        });
    } catch (e) {
        res.status(500).json({ error: "Server error" });
    }
});

// Registro con cifrado AES en la BD
app.post("/registro", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: "Completa todos los campos" });

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, iv);
        let encrypted = cipher.update(password, "utf8", "hex");
        encrypted += cipher.final("hex");

        const sql = "INSERT INTO usuarios (username, password_aes, iv) VALUES (?, ?, ?)";
        db.query(sql, [username, encrypted, iv.toString("hex")], (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: "Este usuario ya existe" });
                return res.status(500).json(err);
            }
            return res.json({ mensaje: "Usuario registrado!" });
        });
    } catch (error) {
        return res.status(500).json({ error: "Error en el servidor" });
    }
});

// Login con Cifrado Hibrido
app.post("/login", async (req, res) => {
    try {
        const { encryptedCredentials, encryptedKey } = req.body;
        if (!encryptedCredentials || !encryptedKey) return res.status(400).json({ error: "Falta el payload para la encriptacion hibrida" });

        let decryptedAesKey;
        try {
            decryptedAesKey = crypto.privateDecrypt(
                {
                    key: privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256",
                },
                Buffer.from(encryptedKey, "base64")
            );
        } catch (e) {
            return res.status(401).json({ error: "Error al desencriptar la llave AES" });
        }

        let credentialsStr;
        try {
            const dataBuffer = Buffer.from(encryptedCredentials, "base64");
            const iv = dataBuffer.subarray(0, 12);
            const tag = dataBuffer.subarray(dataBuffer.length - 16);
            const ciphertext = dataBuffer.subarray(12, dataBuffer.length - 16);

            const decipher = crypto.createDecipheriv("aes-256-gcm", decryptedAesKey, iv);
            decipher.setAuthTag(tag);
            let decrypted = decipher.update(ciphertext);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            credentialsStr = decrypted.toString("utf8");
        } catch (e) {
            return res.status(401).json({ error: "Failed to decrypt credentials payload" });
        }

        const { username, password } = JSON.parse(credentialsStr);

        const sql = "SELECT * FROM usuarios WHERE username=?";
        db.query(sql, [username], async (err, result) => {
            if (err) return res.status(500).json(err);
            if (result.length === 0) return res.status(401).json({ mensaje: "Usuario no encontrado" });

            const user = result[0];
            try {
                const ivBuffer = Buffer.from(user.iv, "hex");
                let decipherDB = crypto.createDecipheriv("aes-256-cbc", AES_KEY, ivBuffer);
                let decryptedPasswordDB = decipherDB.update(user.password_aes, "hex", "utf8");
                decryptedPasswordDB += decipherDB.final("utf8");

                if (password === decryptedPasswordDB) {
                    return res.json({ mensaje: "Usuario logeado!" });
                } else {
                    return res.status(401).json({ mensaje: "Contraseña incorrecta" });
                }
            } catch (e) {
                return res.status(500).json({ error: "Error de integridad de BD en la contraseña" });
            }
        });
    } catch (e) {
        res.status(500).json({ error: "Error en login" });
    }
});

app.listen(5500, () => {
    console.log("Servidor corriendo en puerto 5500");
});