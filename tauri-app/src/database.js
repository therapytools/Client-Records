import Database from '@tauri-apps/plugin-sql';
import CryptoJS from 'crypto-js';

let db = null;
let encryptionKey = null;
let currentUser = null;
let lastAuthError = '';
const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;
const CODE_RESEND_COOLDOWN_MS = 60 * 1000;
const CODE_MAX_PER_HOUR = 5;

const invokeTauriCommand = async (command, args) => {
    const invoke = window?.__TAURI__?.core?.invoke;
    if (typeof invoke !== 'function') {
        throw new Error('Desktop runtime is required for secure credential operations.');
    }
    return invoke(command, args);
};

const randomSecret = () => CryptoJS.lib.WordArray.random(32).toString();

function validateSmtpConfig(smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword) {
    const normalizedHost = (smtpHost || '').trim();
    const normalizedSecurity = (smtpSecurity || '').trim().toLowerCase();

    if (!normalizedHost) {
        return 'SMTP host is required.';
    }

    const parsedPort = Number(smtpPort);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        return 'SMTP port must be a valid port number (1-65535).';
    }

    if (normalizedSecurity !== 'starttls' && normalizedSecurity !== 'tls' && normalizedSecurity !== 'ssl') {
        return 'SMTP security must be STARTTLS, TLS, or SSL.';
    }

    if (!smtpUsername || !smtpFrom || !smtpPassword) {
        return 'SMTP authentication is required (username, from email, and app password).';
    }

    return '';
}

async function enforceCodeRateLimit(database, tableName, normalizedUsername, contextLabel) {
    const now = Date.now();
    const recentRows = await database.select(
        `SELECT created_at FROM ${tableName} WHERE username = $1 ORDER BY created_at DESC LIMIT 1`,
        [normalizedUsername]
    );

    if (recentRows?.length) {
        const lastCreatedAt = Number(recentRows[0].created_at || 0);
        const elapsed = now - lastCreatedAt;
        if (elapsed < CODE_RESEND_COOLDOWN_MS) {
            const waitSeconds = Math.ceil((CODE_RESEND_COOLDOWN_MS - elapsed) / 1000);
            lastAuthError = `Please wait ${waitSeconds}s before requesting another ${contextLabel} code.`;
            return false;
        }
    }

    const hourlyRows = await database.select(
        `SELECT COUNT(*) as count FROM ${tableName} WHERE username = $1 AND created_at >= $2`,
        [normalizedUsername, now - (60 * 60 * 1000)]
    );
    const hourlyCount = Number(hourlyRows?.[0]?.count ?? 0);
    if (hourlyCount >= CODE_MAX_PER_HOUR) {
        lastAuthError = `Too many ${contextLabel} requests. Try again in about an hour.`;
        return false;
    }

    return true;
}

async function ensureSchema(database) {
    await database.execute(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    `);

    const userColumns = await database.select('PRAGMA table_info(users)');
    const existing = new Set((userColumns || []).map(col => col.name));
    const additions = [
        { name: 'email', sql: 'ALTER TABLE users ADD COLUMN email TEXT' },
        { name: 'smtp_host', sql: 'ALTER TABLE users ADD COLUMN smtp_host TEXT' },
        { name: 'smtp_port', sql: 'ALTER TABLE users ADD COLUMN smtp_port INTEGER' },
        { name: 'smtp_security', sql: 'ALTER TABLE users ADD COLUMN smtp_security TEXT' },
        { name: 'smtp_username', sql: 'ALTER TABLE users ADD COLUMN smtp_username TEXT' },
        { name: 'smtp_from', sql: 'ALTER TABLE users ADD COLUMN smtp_from TEXT' },
        { name: 'smtp_password', sql: 'ALTER TABLE users ADD COLUMN smtp_password TEXT' },
        { name: 'recovery_enabled', sql: 'ALTER TABLE users ADD COLUMN recovery_enabled INTEGER DEFAULT 0' },
        { name: 'email_verified', sql: 'ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 1' },
        { name: 'email_verified_at', sql: 'ALTER TABLE users ADD COLUMN email_verified_at INTEGER' }
    ];
    for (const item of additions) {
        if (!existing.has(item.name)) {
            await database.execute(item.sql);
        }
    }

    await database.execute(`
        CREATE TABLE IF NOT EXISTS password_reset_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )
    `);
    await database.execute('CREATE INDEX IF NOT EXISTS idx_password_reset_username ON password_reset_codes(username)');

    await database.execute(`
        CREATE TABLE IF NOT EXISTS email_verification_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )
    `);
    await database.execute('CREATE INDEX IF NOT EXISTS idx_email_verify_username ON email_verification_codes(username)');
}

async function sendEmailVerificationCode(database, normalizedUsername) {
    const rows = await database.select(
        'SELECT username, email, smtp_host, smtp_port, smtp_security, smtp_username, smtp_from, smtp_password, recovery_enabled, email_verified FROM users WHERE username = $1',
        [normalizedUsername]
    );

    if (!rows?.length) {
        lastAuthError = 'Account not found.';
        return false;
    }

    const user = rows[0];
    if (Number(user.email_verified) === 1) {
        lastAuthError = 'Email is already verified. You can log in now.';
        return false;
    }

    if (!user.recovery_enabled || !user.email || !user.smtp_host || !user.smtp_port || !user.smtp_username || !user.smtp_from || !user.smtp_password) {
        lastAuthError = 'SMTP recovery settings are required to verify email.';
        return false;
    }

    const rateAllowed = await enforceCodeRateLimit(database, 'email_verification_codes', normalizedUsername, 'verification');
    if (!rateAllowed) {
        return false;
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = CryptoJS.SHA256(`${normalizedUsername}:verify:${code}`).toString();
    const now = Date.now();
    const expiresAt = now + EMAIL_CODE_TTL_MS;

    await database.execute('DELETE FROM email_verification_codes WHERE username = $1 OR expires_at < $2 OR used = 1', [normalizedUsername, now - (24 * 60 * 60 * 1000)]);
    await database.execute(
        'INSERT INTO email_verification_codes (username, code_hash, expires_at, attempts, used, created_at) VALUES ($1, $2, $3, 0, 0, $4)',
        [normalizedUsername, codeHash, expiresAt, now]
    );

    try {
        console.log('[DEBUG] Sending verification email with args:', {
            username: normalizedUsername,
            toEmail: user.email,
            smtpHost: user.smtp_host,
            smtpPort: Number(user.smtp_port),
            smtpSecurity: (user.smtp_security || 'starttls').toLowerCase(),
            smtpUsername: user.smtp_username,
            smtpPassword: user.smtp_password ? '***' : 'MISSING',
            fromEmail: user.smtp_from,
            code
        });
        await invokeTauriCommand('send_email_verification_email', {
            args: {
                username: normalizedUsername,
                toEmail: user.email,
                smtpHost: user.smtp_host,
                smtpPort: Number(user.smtp_port),
                smtpSecurity: (user.smtp_security || 'starttls').toLowerCase(),
                smtpUsername: user.smtp_username,
                smtpPassword: user.smtp_password,
                fromEmail: user.smtp_from,
                code
            }
        });
        console.log('[DEBUG] Verification email sent successfully');
    } catch (error) {
        console.error('[DEBUG] Verification email error:', error);
        const detail = typeof error === 'string' ? ` ${error}` : (error?.message ? ` ${error.message}` : '');
        lastAuthError = `Verification email failed to send.${detail}`;
        return false;
    }

    lastAuthError = `Verification code sent to ${user.email}.`;
    return true;
}

async function getOrMigrateEncryptionKey(normalizedUsername, password, database) {
    // Derive encryption key from password (no keychain)
    return CryptoJS.SHA256(password + normalizedUsername).toString();
}

async function getDb() {
    if (!db) {
        try {
            db = await Database.load('sqlite:client_records.db');
            await ensureSchema(db);
            await db.execute(`
                CREATE TABLE IF NOT EXISTS app_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL
                )
            `);
            lastAuthError = '';
        } catch (error) {
            console.error("Database load/init failed:", error);
            const rawMessage = error?.message || String(error);
            lastAuthError = `Database unavailable. Raw error: ${rawMessage}. Check console for details.`;
            db = null; // Ensure db is null on failure
            throw new Error(lastAuthError);
        }
    }
    return db;
}

export async function checkFirstLogin() {
    try {
        const database = await getDb();
        const result = await database.select('SELECT COUNT(*) as count FROM users');
        lastAuthError = '';
        return Number(result?.[0]?.count ?? 0) === 0;
    } catch (error) {
        try {
            await new Promise((resolve) => setTimeout(resolve, 300));
            db = null;
            const database = await getDb();
            const result = await database.select('SELECT COUNT(*) as count FROM users');
            lastAuthError = '';
            return Number(result?.[0]?.count ?? 0) === 0;
        } catch (retryError) {
            console.error("Failed to check first login:", retryError);
            if (!lastAuthError) {
                const rawMessage = retryError?.message || String(retryError);
                lastAuthError = `Database unavailable: ${rawMessage}`;
            }
            return false;
        }
    }
}

export async function createUser(username, password, email = '', recoveryConfig = null) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedEmail = (email || '').trim();
        if (!normalizedUsername) {
            lastAuthError = 'Username is required.';
            return false;
        }

        if (!normalizedEmail) {
            lastAuthError = 'Email is required for account recovery.';
            return false;
        }

        const existingUser = await database.select('SELECT id FROM users WHERE username = $1', [normalizedUsername]);
        if (existingUser?.length) {
            lastAuthError = 'User already exists. Please log in.';
            return false;
        }

        const passwordHash = CryptoJS.SHA256(password).toString();
        const smtpHost = (recoveryConfig?.smtpHost || '').trim();
        const smtpPort = Number(recoveryConfig?.smtpPort || 0);
        const smtpSecurity = (recoveryConfig?.smtpSecurity || 'starttls').trim().toLowerCase();
        const smtpUsername = (recoveryConfig?.smtpUsername || '').trim();
        const smtpFrom = (recoveryConfig?.smtpFrom || normalizedEmail).trim();
        const smtpPassword = (recoveryConfig?.smtpPassword || '').trim();
        const smtpValidationError = validateSmtpConfig(smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword);
        if (smtpValidationError) {
            lastAuthError = smtpValidationError;
            return false;
        }
        const recoveryEnabled = smtpHost && smtpPort > 0 && smtpUsername && smtpFrom && smtpPassword ? 1 : 0;
        if (!recoveryEnabled) {
            lastAuthError = 'SMTP settings are required for email verification.';
            return false;
        }

        await database.execute(
            'INSERT INTO users (username, password_hash, email, smtp_host, smtp_port, smtp_security, smtp_username, smtp_from, smtp_password, recovery_enabled, email_verified, email_verified_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, NULL)',
            [normalizedUsername, passwordHash, normalizedEmail, smtpHost, smtpPort || null, smtpSecurity, smtpUsername, smtpFrom, smtpPassword, recoveryEnabled]
        );
        
        const sent = await sendEmailVerificationCode(database, normalizedUsername);
        if (!sent) {
            await database.execute('DELETE FROM users WHERE username = $1', [normalizedUsername]);
            await database.execute('DELETE FROM email_verification_codes WHERE username = $1', [normalizedUsername]);
            await database.execute('DELETE FROM password_reset_codes WHERE username = $1', [normalizedUsername]);

            return false;
        }

        encryptionKey = null;
        currentUser = null;
        lastAuthError = '';
        return true;
    } catch (error) {
        console.error("Failed to create user:", error);
        lastAuthError = 'Failed to create user. Please try again.';
        return false;
    }
}

export async function loginUser(username, password) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const passwordHash = CryptoJS.SHA256(password).toString();
        const result = await database.select('SELECT * FROM users WHERE username = $1 AND password_hash = $2', [normalizedUsername, passwordHash]);
        
        if (result.length > 0) {
            if (Number(result[0].email_verified) !== 1) {
                lastAuthError = 'Email not verified. Enter your verification code to continue.';
                return false;
            }
            encryptionKey = await getOrMigrateEncryptionKey(normalizedUsername, password, database);
            currentUser = normalizedUsername;
            lastAuthError = '';
            return true;
        }
        lastAuthError = 'Incorrect username or password.';
        return false;
    } catch (error) {
        console.error("Failed to login:", error);
        lastAuthError = 'Login failed. Please restart the app.';
        return false;
    }
}

export async function changePassword(currentPassword, newPassword) {
    if (!db || !currentUser || !encryptionKey) return false;

    try {
        const currentPasswordHash = CryptoJS.SHA256(currentPassword).toString();
        const userResult = await db.select(
            'SELECT password_hash FROM users WHERE username = $1',
            [currentUser]
        );

        if (!userResult?.length || userResult[0].password_hash !== currentPasswordHash) {
            return false;
        }

        const newPasswordHash = CryptoJS.SHA256(newPassword).toString();
        await db.execute(
            'UPDATE users SET password_hash = $1 WHERE username = $2',
            [newPasswordHash, currentUser]
        );

        return true;
    } catch (error) {
        console.error('Failed to change password:', error);
        return false;
    }
}

export function getLastAuthError() {
    return lastAuthError;
}

export async function requestPasswordReset(username) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        if (!normalizedUsername) {
            lastAuthError = 'Username is required.';
            return false;
        }

        const rows = await database.select(
            'SELECT username, email, smtp_host, smtp_port, smtp_security, smtp_username, smtp_from, smtp_password, recovery_enabled, email_verified FROM users WHERE username = $1',
            [normalizedUsername]
        );
        if (!rows?.length) {
            lastAuthError = 'Account not found.';
            return false;
        }

        const user = rows[0];
        if (Number(user.email_verified) !== 1) {
            lastAuthError = 'Email must be verified before password recovery can be used.';
            return false;
        }

        if (!user.recovery_enabled || !user.email || !user.smtp_host || !user.smtp_port || !user.smtp_username || !user.smtp_from || !user.smtp_password) {
            lastAuthError = 'Recovery email is not configured for this account.';
            return false;
        }

        const rateAllowed = await enforceCodeRateLimit(database, 'password_reset_codes', normalizedUsername, 'reset');
        if (!rateAllowed) {
            return false;
        }

        const code = String(Math.floor(100000 + Math.random() * 900000));
        const codeHash = CryptoJS.SHA256(`${normalizedUsername}:${code}`).toString();
        const now = Date.now();
        const expiresAt = now + (10 * 60 * 1000);

        await database.execute('DELETE FROM password_reset_codes WHERE username = $1 OR expires_at < $2 OR used = 1', [normalizedUsername, now - (24 * 60 * 60 * 1000)]);
        await database.execute(
            'INSERT INTO password_reset_codes (username, code_hash, expires_at, attempts, used, created_at) VALUES ($1, $2, $3, 0, 0, $4)',
            [normalizedUsername, codeHash, expiresAt, now]
        );

        await invokeTauriCommand('send_password_reset_email', {
            args: {
                username: normalizedUsername,
                toEmail: user.email,
                smtpHost: user.smtp_host,
                smtpPort: Number(user.smtp_port),
                smtpSecurity: (user.smtp_security || 'starttls').toLowerCase(),
                smtpUsername: user.smtp_username,
                smtpPassword: user.smtp_password,
                fromEmail: user.smtp_from,
                code
            }
        });

        lastAuthError = `Reset code sent to ${user.email}.`;
        return true;
    } catch (error) {
        console.error('Failed to request password reset:', error);
        lastAuthError = 'Failed to send reset code. Check SMTP settings.';
        return false;
    }
}

export async function requestEmailVerification(username) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        if (!normalizedUsername) {
            lastAuthError = 'Username is required.';
            return false;
        }

        const rows = await database.select(
            'SELECT id FROM users WHERE username = $1',
            [normalizedUsername]
        );
        if (!rows?.length) {
            lastAuthError = 'Account not found.';
            return false;
        }

        return sendEmailVerificationCode(database, normalizedUsername);
    } catch (error) {
        console.error('Failed to request email verification:', error);
        lastAuthError = `Failed to send verification code: ${error}`;
        return false;
    }
}

export async function updateRecoverySettings(username, password, email = '', recoveryConfig = null, sendVerificationCode = true) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedPassword = (password || '').trim();
        const normalizedEmail = (email || '').trim();

        if (!normalizedUsername || !normalizedPassword) {
            lastAuthError = 'Username and password are required.';
            return false;
        }

        if (!normalizedEmail) {
            lastAuthError = 'Recovery email is required.';
            return false;
        }

        const passwordHash = CryptoJS.SHA256(normalizedPassword).toString();
        const matched = await database.select(
            'SELECT id FROM users WHERE username = $1 AND password_hash = $2',
            [normalizedUsername, passwordHash]
        );

        if (!matched?.length) {
            lastAuthError = 'Incorrect username or password.';
            return false;
        }

        const smtpHost = (recoveryConfig?.smtpHost || '').trim();
        const smtpPort = Number(recoveryConfig?.smtpPort || 0);
        const smtpSecurity = (recoveryConfig?.smtpSecurity || 'starttls').trim().toLowerCase();
        const smtpUsername = (recoveryConfig?.smtpUsername || '').trim();
        const smtpFrom = (recoveryConfig?.smtpFrom || normalizedEmail).trim();
        const smtpPassword = (recoveryConfig?.smtpPassword || '').trim();

        const smtpValidationError = validateSmtpConfig(smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword);
        if (smtpValidationError) {
            lastAuthError = smtpValidationError;
            return false;
        }

        if (!smtpHost || smtpPort <= 0 || !smtpUsername || !smtpFrom || !smtpPassword) {
            lastAuthError = 'Complete all SMTP settings to continue.';
            return false;
        }

        await database.execute(
            'UPDATE users SET email = $1, smtp_host = $2, smtp_port = $3, smtp_security = $4, smtp_username = $5, smtp_from = $6, smtp_password = $7, recovery_enabled = 1, email_verified = 0, email_verified_at = NULL WHERE username = $8',
            [normalizedEmail, smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword, normalizedUsername]
        );

        if (sendVerificationCode) {
            const sent = await sendEmailVerificationCode(database, normalizedUsername);
            if (sent) {
                lastAuthError = 'SMTP settings updated. Verification code sent to your email.';
                return true;
            } else {
                const warningMessage = lastAuthError || 'Verification email failed to send.';
                lastAuthError = `SMTP settings updated. ${warningMessage}`;
                return true;
            }
        } else {
            lastAuthError = 'SMTP settings updated.';
            return true;
        }
    } catch (error) {
        console.error('Failed to update recovery settings:', error);
        lastAuthError = `Failed to update SMTP settings: ${error}`;
        return false;
    }
}

export async function getRecoverySettings(username, password) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedPassword = (password || '').trim();

        if (!normalizedUsername || !normalizedPassword) {
            lastAuthError = 'Username and password are required.';
            return null;
        }

        const passwordHash = CryptoJS.SHA256(normalizedPassword).toString();
        const rows = await database.select(
            'SELECT email, smtp_host, smtp_port, smtp_security, smtp_username, smtp_from FROM users WHERE username = $1 AND password_hash = $2',
            [normalizedUsername, passwordHash]
        );

        if (!rows?.length) {
            lastAuthError = 'Incorrect username or password.';
            return null;
        }

        const row = rows[0];
        lastAuthError = '';
        return {
            email: row.email || '',
            smtpHost: row.smtp_host || 'smtp.gmail.com',
            smtpPort: Number(row.smtp_port || 587),
            smtpSecurity: (row.smtp_security || 'starttls').toLowerCase(),
            smtpUsername: row.smtp_username || '',
            smtpFrom: row.smtp_from || ''
        };
    } catch (error) {
        console.error('Failed to load recovery settings:', error);
        lastAuthError = 'Failed to load SMTP settings.';
        return null;
    }
}

export async function testSmtpSettings(username, password, email = '', recoveryConfig = null) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedPassword = (password || '').trim();
        const normalizedEmail = (email || '').trim();

        if (!normalizedUsername || !normalizedPassword || !normalizedEmail) {
            lastAuthError = 'Username, password, and recovery email are required.';
            return false;
        }

        const passwordHash = CryptoJS.SHA256(normalizedPassword).toString();
        const rows = await database.select(
            'SELECT id FROM users WHERE username = $1 AND password_hash = $2',
            [normalizedUsername, passwordHash]
        );
        if (!rows?.length) {
            lastAuthError = 'Incorrect username or password.';
            return false;
        }

        const smtpHost = (recoveryConfig?.smtpHost || '').trim();
        const smtpPort = Number(recoveryConfig?.smtpPort || 0);
        const smtpSecurity = (recoveryConfig?.smtpSecurity || 'starttls').trim().toLowerCase();
        const smtpUsername = (recoveryConfig?.smtpUsername || '').trim();
        const smtpFrom = (recoveryConfig?.smtpFrom || normalizedEmail).trim();
        const smtpPassword = (recoveryConfig?.smtpPassword || '').trim();

        const smtpValidationError = validateSmtpConfig(smtpHost, smtpPort, smtpSecurity, smtpUsername, smtpFrom, smtpPassword);
        if (smtpValidationError) {
            lastAuthError = smtpValidationError;
            return false;
        }

        await invokeTauriCommand('send_smtp_test_email', {
            args: {
                toEmail: normalizedEmail,
                smtpHost,
                smtpPort,
                smtpSecurity,
                smtpUsername,
                smtpPassword,
                fromEmail: smtpFrom
            }
        });

        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to send SMTP test email:', error);
        const detail = error?.message ? ` Details: ${error.message}` : '';
        lastAuthError = `SMTP test failed. Check host, port, security, username, and app password.${detail}`;
        return false;
    }
}

export async function confirmEmailVerification(username, code) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedCode = (code || '').trim();

        if (!normalizedUsername || !normalizedCode) {
            lastAuthError = 'Username and verification code are required.';
            return false;
        }

        const userRows = await database.select('SELECT email_verified FROM users WHERE username = $1', [normalizedUsername]);
        if (!userRows?.length) {
            lastAuthError = 'Account not found.';
            return false;
        }

        if (Number(userRows[0].email_verified) === 1) {
            lastAuthError = '';
            return true;
        }

        const rows = await database.select(
            'SELECT id, code_hash, attempts, expires_at, used FROM email_verification_codes WHERE username = $1 ORDER BY created_at DESC LIMIT 1',
            [normalizedUsername]
        );

        if (!rows?.length) {
            lastAuthError = 'No active verification code found. Request a new code.';
            return false;
        }

        const row = rows[0];
        const now = Date.now();
        if (row.used || Number(row.expires_at) < now) {
            lastAuthError = 'Verification code expired. Request a new code.';
            return false;
        }

        if (Number(row.attempts) >= 5) {
            lastAuthError = 'Too many failed attempts. Request a new code.';
            return false;
        }

        const expectedHash = CryptoJS.SHA256(`${normalizedUsername}:verify:${normalizedCode}`).toString();
        if (expectedHash !== row.code_hash) {
            const attempts = Number(row.attempts) + 1;
            const used = attempts >= 5 ? 1 : 0;
            await database.execute('UPDATE email_verification_codes SET attempts = $1, used = $2 WHERE id = $3', [attempts, used, row.id]);
            lastAuthError = used
                ? 'Too many failed attempts. Request a new code.'
                : `Invalid code. ${Math.max(0, 5 - attempts)} attempt(s) remaining.`;
            return false;
        }

        const verifiedAt = Date.now();
        await database.execute('UPDATE users SET email_verified = 1, email_verified_at = $1 WHERE username = $2', [verifiedAt, normalizedUsername]);
        await database.execute('UPDATE email_verification_codes SET used = 1 WHERE id = $1', [row.id]);
        await database.execute('DELETE FROM email_verification_codes WHERE username = $1 AND id != $2', [normalizedUsername, row.id]);

        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to confirm email verification:', error);
        lastAuthError = 'Email verification failed. Please try again.';
        return false;
    }
}

export async function confirmPasswordReset(username, code, newPassword) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedCode = (code || '').trim();
        if (!normalizedUsername || !normalizedCode || !newPassword) {
            lastAuthError = 'Username, code, and new password are required.';
            return false;
        }

        if (newPassword.length < 8) {
            lastAuthError = 'New password must be at least 8 characters.';
            return false;
        }

        const rows = await database.select(
            'SELECT id, code_hash, attempts, expires_at, used FROM password_reset_codes WHERE username = $1 ORDER BY created_at DESC LIMIT 1',
            [normalizedUsername]
        );

        if (!rows?.length) {
            lastAuthError = 'No active reset request found. Request a new code.';
            return false;
        }

        const row = rows[0];
        const now = Date.now();
        if (row.used || Number(row.expires_at) < now) {
            lastAuthError = 'Reset code expired. Request a new code.';
            return false;
        }

        if (Number(row.attempts) >= 5) {
            lastAuthError = 'Too many failed attempts. Request a new code.';
            return false;
        }

        const expectedHash = CryptoJS.SHA256(`${normalizedUsername}:${normalizedCode}`).toString();
        if (expectedHash !== row.code_hash) {
            const attempts = Number(row.attempts) + 1;
            const used = attempts >= 5 ? 1 : 0;
            await database.execute('UPDATE password_reset_codes SET attempts = $1, used = $2 WHERE id = $3', [attempts, used, row.id]);
            lastAuthError = used
                ? 'Too many failed attempts. Request a new code.'
                : `Invalid code. ${Math.max(0, 5 - attempts)} attempt(s) remaining.`;
            return false;
        }

        const newPasswordHash = CryptoJS.SHA256(newPassword).toString();
        await database.execute('UPDATE users SET password_hash = $1 WHERE username = $2', [newPasswordHash, normalizedUsername]);
        await database.execute('UPDATE password_reset_codes SET used = 1 WHERE id = $1', [row.id]);
        await database.execute('DELETE FROM password_reset_codes WHERE username = $1 AND id != $2', [normalizedUsername, row.id]);

        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to confirm password reset:', error);
        lastAuthError = 'Password reset failed. Please try again.';
        return false;
    }
}

export async function deleteUserAccount(username, password) {
    try {
        const database = await getDb();
        const normalizedUsername = (username || '').trim();
        const normalizedPassword = (password || '').trim();
        if (!normalizedUsername || !normalizedPassword) {
            lastAuthError = 'Username and password are required.';
            return false;
        }

        const passwordHash = CryptoJS.SHA256(normalizedPassword).toString();
        const matched = await database.select(
            'SELECT id FROM users WHERE username = $1 AND password_hash = $2',
            [normalizedUsername, passwordHash]
        );

        if (!matched?.length) {
            lastAuthError = 'Incorrect username or password.';
            return false;
        }

        await database.execute('DELETE FROM password_reset_codes WHERE username = $1', [normalizedUsername]);
        await database.execute('DELETE FROM email_verification_codes WHERE username = $1', [normalizedUsername]);
        await database.execute('DELETE FROM users WHERE username = $1', [normalizedUsername]);
        await database.execute('DELETE FROM app_state WHERE key = $1', ['main_state']);

        if (currentUser === normalizedUsername) {
            encryptionKey = null;
            currentUser = null;
        }

        db = null;
        lastAuthError = '';
        return true;
    } catch (error) {
        console.error('Failed to delete account:', error);
        lastAuthError = 'Failed to delete account.';
        return false;
    }
}

const sqlEscape = (value) => {
    if (value === null || value === undefined) return 'NULL';
    if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'NULL';
    if (typeof value === 'boolean') return value ? '1' : '0';
    return `'${String(value).replace(/'/g, "''")}'`;
};

export async function exportEncryptedSqlDump() {
    if (!db || !encryptionKey) {
        throw new Error('Database is not initialized. Please log in first.');
    }

    const schemaRows = await db.select(
        "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    );

    let sqlDump = '-- Client Records SQL Export\n';
    sqlDump += `-- Generated: ${new Date().toISOString()}\n\n`;

    for (const row of schemaRows) {
        sqlDump += `${row.sql};\n`;

        const rows = await db.select(`SELECT * FROM ${row.name}`);
        if (rows.length > 0) {
            const columns = Object.keys(rows[0]);
            for (const record of rows) {
                const values = columns.map((column) => sqlEscape(record[column])).join(', ');
                sqlDump += `INSERT INTO ${row.name} (${columns.join(', ')}) VALUES (${values});\n`;
            }
        }

        sqlDump += '\n';
    }

    const encryptedSqlDump = CryptoJS.AES.encrypt(sqlDump, encryptionKey).toString();
    return {
        format: 'client-records-sql-export',
        encrypted: true,
        algorithm: 'AES',
        createdAt: new Date().toISOString(),
        data: encryptedSqlDump
    };
}

const splitSqlStatements = (sqlScript) => {
    const statements = [];
    let current = '';
    let inSingleQuote = false;

    for (let index = 0; index < sqlScript.length; index += 1) {
        const char = sqlScript[index];
        const nextChar = sqlScript[index + 1];

        if (char === "'" && inSingleQuote && nextChar === "'") {
            current += "''";
            index += 1;
            continue;
        }

        if (char === "'") {
            inSingleQuote = !inSingleQuote;
            current += char;
            continue;
        }

        if (!inSingleQuote && char === ';') {
            const trimmed = current.trim();
            if (trimmed && !trimmed.startsWith('--')) {
                statements.push(trimmed);
            }
            current = '';
            continue;
        }

        current += char;
    }

    const trailing = current.trim();
    if (trailing && !trailing.startsWith('--')) {
        statements.push(trailing);
    }

    return statements;
};

export async function importSqlDump(sqlDumpText) {
    if (!db) {
        throw new Error('Database is not initialized. Please log in first.');
    }

    if (typeof sqlDumpText !== 'string' || sqlDumpText.trim().length === 0) {
        throw new Error('SQL import file is empty or invalid.');
    }

    const statements = splitSqlStatements(sqlDumpText);
    if (statements.length === 0) {
        throw new Error('No SQL statements found in import file.');
    }

    try {
        await db.execute('BEGIN TRANSACTION');
        await db.execute('PRAGMA foreign_keys = OFF');

        const tableRows = await db.select("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");
        for (const row of tableRows) {
            await db.execute(`DROP TABLE IF EXISTS ${row.name}`);
        }

        for (const statement of statements) {
            await db.execute(statement);
        }

        await db.execute('PRAGMA foreign_keys = ON');
        await db.execute('COMMIT');
    } catch (error) {
        try {
            await db.execute('ROLLBACK');
            await db.execute('PRAGMA foreign_keys = ON');
        } catch (_rollbackError) {
        }
        throw error;
    }
}

export async function importEncryptedSqlDump(exportPayload) {
    if (!db || !encryptionKey) {
        throw new Error('Database is not initialized. Please log in first.');
    }

    if (!exportPayload || typeof exportPayload !== 'object') {
        throw new Error('Invalid encrypted SQL import payload.');
    }

    if (exportPayload.format !== 'client-records-sql-export' || typeof exportPayload.data !== 'string') {
        throw new Error('Unsupported SQL import format.');
    }

    const decryptedBytes = CryptoJS.AES.decrypt(exportPayload.data, encryptionKey);
    const decryptedSql = decryptedBytes.toString(CryptoJS.enc.Utf8);
    if (!decryptedSql) {
        throw new Error('Failed to decrypt SQL import. Ensure you are logged in as the correct user.');
    }

    await importSqlDump(decryptedSql);
}

export async function saveState(state) {
    if (!db || !encryptionKey) return false;
    
    try {
        const stateString = JSON.stringify(state);
        const encryptedState = CryptoJS.AES.encrypt(stateString, encryptionKey).toString();
        
        await db.execute(
            'INSERT INTO app_state (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = $2',
            ['main_state', encryptedState]
        );
        return true;
    } catch (error) {
        console.error("Failed to save state to database:", error);
        return false;
    }
}

export async function loadState() {
    if (!db || !encryptionKey) return null;
    
    try {
        const result = await db.select('SELECT value FROM app_state WHERE key = $1', ['main_state']);
        
        if (result && result.length > 0) {
            const encryptedState = result[0].value;
            const decryptedBytes = CryptoJS.AES.decrypt(encryptedState, encryptionKey);
            const decryptedString = decryptedBytes.toString(CryptoJS.enc.Utf8);
            
            if (!decryptedString) {
                throw new Error("Failed to decrypt data. Incorrect password?");
            }
            
            return JSON.parse(decryptedString);
        }
        return null;
    } catch (error) {
        console.error("Failed to load state from database:", error);
        throw error; // Re-throw to handle incorrect password
    }
}

export function isDatabaseInitialized() {
    return db !== null && encryptionKey !== null;
}
