import express from 'express';
import multer from 'multer';
import cors from 'cors';
import fs from 'fs';
import http from 'http';
import https from 'https';
import { exec } from 'child_process';
import path from 'path';
import { parse } from 'csv-parse/sync';
import { WebSocketServer, WebSocket } from 'ws';
import mammoth from 'mammoth';
import nodemailer from 'nodemailer';

const app = express();
const HTTP_PORT = 80;
const HTTPS_PORT = 443;
const upload = multer({ dest: 'uploads/' });

// CORS: Allow all origins with credentials
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));

// Enhanced logging
const LOG_FILE_PATH = './logs/server.log';
function appendLogToFile(message) {
  try {
    fs.mkdirSync('./logs', { recursive: true });
    fs.appendFileSync(LOG_FILE_PATH, message + '\n');
  } catch (e) {
    console.error('Failed to write to log file:', e.message);
  }
}

const log = (message, level = 'INFO') => {
  const timestamp = new Date().toISOString();
  const formatted = `[${timestamp}] ${level}: ${message}`;
  console.log(formatted);
  appendLogToFile(formatted);
};

// Endpoint to get email list
app.get('/api/emails', (req, res) => {
  log('Fetching email list from emails.csv');
  fs.readFile('emails.csv', 'utf8', (err, data) => {
    if (err) {
      log(`Failed to read emails.csv: ${err.message}`, 'ERROR');
      return res.status(500).json({ error: 'Could not read email list' });
    }
    try {
      const lines = data.split(/\r?\n/).filter(Boolean);
      const emails = lines.map(line => {
        const [first, last, email] = line.split(',');
        if (!email) throw new Error('Invalid CSV format: missing email');
        return { name: `${first || ''} ${last || ''}`.trim() || 'No Name', email: email.trim() };
      });
      log(`Successfully fetched ${emails.length} emails`);
      res.json({ emails });
    } catch (err) {
      log(`Error parsing emails.csv: ${err.message}`, 'ERROR');
      res.status(400).json({ error: 'Invalid email list format' });
    }
  });
});

// Endpoint to preview recipients CSV
app.post('/api/preview', upload.single('recipients'), (req, res) => {
  const recipientsFile = req.file;
  if (!recipientsFile) {
    log('No recipients CSV uploaded for preview', 'ERROR');
    return res.status(400).json({ error: 'No recipients CSV provided' });
  }
  if (path.extname(recipientsFile.originalname).toLowerCase() !== '.csv') {
    log(`Invalid file type for preview: ${recipientsFile.originalname}`, 'ERROR');
    fs.unlink(recipientsFile.path, () => {});
    return res.status(400).json({ error: 'Only CSV files are allowed' });
  }
  log(`Previewing recipients CSV: ${recipientsFile.originalname}`);
  fs.readFile(recipientsFile.path, 'utf8', (err, data) => {
    if (err) {
      log(`Failed to read recipients CSV: ${err.message}`, 'ERROR');
      fs.unlink(recipientsFile.path, () => {});
      return res.status(500).json({ error: 'Failed to read recipients CSV' });
    }
    try {
      const records = parse(data, { skip_empty_lines: true });
      const recipients = records
        .map(row => {
          if (!row[2]) throw new Error('Invalid CSV format: missing email');
          return row[2].trim();
        })
        .filter(Boolean);
      log(`Previewed ${recipients.length} recipients`);
      fs.unlink(recipientsFile.path, () => {});
      res.json({ recipients });
    } catch (e) {
      log(`Error parsing recipients CSV: ${e.message}`, 'ERROR');
      fs.unlink(recipientsFile.path, () => {});
      res.status(400).json({ error: 'Invalid CSV format' });
    }
  });
});

// Multer for attachments and recipients
const uploadFields = upload.fields([
  { name: 'attachments', maxCount: 2 },
  { name: 'recipients', maxCount: 1 },
]);

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  host: 'smtp.email.eu-frankfurt-1.oci.oraclecloud.com',
  port: 587,
  secure: false,
  auth: {
    user: 'ocid1.user.oc1..aaaaaaaaxiz77zaakub67voy326ftfmhcm23xiifb3rrs22gvkyu2bni5eka@ocid1.tenancy.oc1..aaaaaaaayg4ulvshtq35735jbqjph75pyxmqlzvfm4cajgfii77i2m4i54ba.88.com',
    pass: 'X9qkh&i$kgzK-nlV$}xt',
  },
  tls: {
    rejectUnauthorized: false,
  },
});

// Load users.json
let users;
try {
  users = JSON.parse(fs.readFileSync('./users.json', 'utf8'));
} catch (e) {
  log(`Failed to load users.json: ${e.message}`, 'ERROR');
  process.exit(1);
}

// Load SSL certificates with fallback
let credentials;
let useHttps = true;
try {
  const privateKey = fs.readFileSync('./privkey.pem', 'utf8');
  const certificate = fs.readFileSync('./fullchain.pem', 'utf8');
  credentials = { key: privateKey, cert: certificate };
  log('SSL certificates loaded successfully');
} catch (e) {
  log(`Failed to load SSL certificates: ${e.message}. Falling back to HTTP.`, 'WARNING');
  useHttps = false;
}

// Create HTTP and HTTPS servers
const httpServer = http.createServer(app);
let httpsServer;
if (useHttps) {
  httpsServer = https.createServer(credentials, app);
}

// Initialize WebSocket servers
let wss, wsServer;
try {
  if (useHttps) {
    wss = new WebSocketServer({ server: httpsServer });
    log('WebSocket Secure (WSS) server initialized on HTTPS');
  }
  wsServer = new WebSocketServer({ server: httpServer });
  log('WebSocket (WS) server initialized on HTTP');
} catch (err) {
  log(`Failed to initialize WebSocket servers: ${err.message}`, 'ERROR');
  process.exit(1);
}

// WebSocket event handlers for both WS and WSS
const setupWebSocket = (server, protocol) => {
  server.on('connection', (ws, req) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const connectTime = new Date().toISOString();
    log(`[${protocol}-CONNECT] New client from ${clientIp} at ${connectTime}`);
    log(`[${protocol}-CONNECT] Request headers: ${JSON.stringify(req.headers)}`);
    log(`[${protocol}-CONNECT] Total connected clients: ${server.clients.size}`);

    ws.on('message', (message) => {
      const msgSize = Buffer.byteLength(message);
      log(`[${protocol}-MESSAGE] ${clientIp}: Received message of size ${msgSize} bytes`);
      try {
        const data = message.toString();
        log(`[${protocol}-MESSAGE] ${clientIp}: Content: ${data}`);
        broadcastLog(`Client message via ${protocol}: ${data}`, server);
      } catch (err) {
        log(`[${protocol}-MESSAGE-ERROR] ${clientIp}: Error processing message: ${err.stack || err.message}`, 'ERROR');
      }
    });

    ws.on('error', (error) => {
      log(`[${protocol}-ERROR] ${clientIp}: ${error.stack || error.message}`, 'ERROR');
    });

    ws.on('close', (code, reason) => {
      const disconnectTime = new Date().toISOString();
      log(`[${protocol}-CLOSE] ${clientIp} at ${disconnectTime} (code: ${code}, reason: ${reason || 'none'})`);
      log(`[${protocol}-CLOSE] Total connected clients: ${server.clients.size}`);
    });
  });

  server.on('error', (error) => {
    log(`[${protocol}-SERVER-ERROR] ${error.message}`, 'ERROR');
  });
};

// Apply WebSocket handlers
if (useHttps) setupWebSocket(wss, 'WSS');
setupWebSocket(wsServer, 'WS');

// Broadcast function for WebSocket messages
function broadcastLog(message, server) {
  const timestamp = new Date().toISOString();
  const formattedMessage = `[${timestamp}] ${message}`;
  server.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(formattedMessage);
      } catch (err) {
        log(`Failed to send message to client: ${err.message}`, 'ERROR');
      }
    }
  });
}

// Middleware to log HTTP requests
app.use(express.json());
app.use((req, res, next) => {
  const protocol = req.secure ? 'HTTPS' : 'HTTP';
  log(`[${protocol}-REQ-START] ${req.method} ${req.url} from ${req.ip}`);
  res.on('finish', () => {
    log(`[${protocol}-REQ-END] ${req.method} ${req.url} from ${req.ip} - Status: ${res.statusCode}`);
  });
  const logMsg = `${protocol} ${req.method} ${req.url} from ${req.ip}`;
  log(logMsg);
  if (useHttps) broadcastLog(logMsg, wss);
  broadcastLog(logMsg, wsServer);
  next();
});

// Helper: log sent email
function logSentEmail({ username, recipient, subject }) {
  const timestamp = new Date().toISOString();
  const entry = `${timestamp} | user: ${username} | to: ${recipient} | subject: ${subject}`;
  try {
    fs.mkdirSync('./logs', { recursive: true });
    fs.appendFileSync('./logs/emails_sent.log', entry + '\n');
    fs.appendFileSync(`./logs/sent_${username}.log`, entry + '\n');
  } catch (e) {
    log(`Failed to write sent email log: ${e.message}`, 'ERROR');
  }
}

// Helper: archive email
function archiveEmail({ username, recipient, subject, body, attachments, timestamp }) {
  const archiveFile = './logs/sent_emails_archive.json';
  try {
    fs.mkdirSync('./logs', { recursive: true });
    let archives = [];
    if (fs.existsSync(archiveFile)) {
      archives = JSON.parse(fs.readFileSync(archiveFile, 'utf8'));
    }
    archives.push({
      timestamp,
      username,
      recipient,
      subject,
      body,
      attachments: attachments.map(att => ({
        filename: att.originalname,
        path: att.path
      }))
    });
    fs.writeFileSync(archiveFile, JSON.stringify(archives, null, 2));
    log(`Archived email to ${recipient}`);
  } catch (e) {
    log(`Failed to archive email: ${e.message}`, 'ERROR');
  }
}

// API: login
app.post('/api/login', express.json(), (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    log(`Login failed for username: ${username}`, 'ERROR');
    return res.status(401).json({ error: 'Authentication failed' });
  }
  log(`User logged in: ${username}`);
  res.json({ success: true });
});

// API: get sent emails
app.post('/api/sent-emails', express.json(), (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    log(`Sent-emails access denied for username: ${username}`, 'ERROR');
    return res.status(401).json({ error: 'Authentication failed' });
  }
  const filePath = `./logs/sent_${username}.log`;
  let lines = [];
  try {
    if (fs.existsSync(filePath)) {
      lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
    }
  } catch (e) {
    log(`Failed to read sent emails log for ${username}: ${e.message}`, 'ERROR');
  }
  res.json({ emails: lines });
});

// === GLOBAL EMAIL QUEUE AND RATE LIMITER ===
const EMAILS_PER_MINUTE = 9;
const emailQueue = [];
let queueStatus = {
  pending: [], // { jobId, username, recipient, subject, enqueuedAt }
  processing: [], // { jobId, username, recipient, subject, startedAt }
  lastSent: [], // { jobId, username, recipient, subject, sentAt, status, error }
  errors: [], // { jobId, username, recipient, subject, error, failedAt }
};
let jobIdCounter = 1;

function updateQueueStatus() {
  queueStatus.pending = emailQueue.map(job => ({
    jobId: job.jobId,
    username: job.username,
    recipient: job.recipient,
    subject: job.subject,
    enqueuedAt: job.enqueuedAt,
  }));
}

// Worker: process up to 9 emails per minute
setInterval(async () => {
  let processed = 0;
  while (emailQueue.length > 0 && processed < EMAILS_PER_MINUTE) {
    const job = emailQueue.shift();
    queueStatus.processing.push({
      jobId: job.jobId,
      username: job.username,
      recipient: job.recipient,
      subject: job.subject,
      startedAt: new Date().toISOString(),
    });
    try {
      await transporter.sendMail(job.mailOptions);
      logSentEmail({ username: job.username, recipient: job.recipient, subject: job.subject });
      archiveEmail({
        username: job.username,
        recipient: job.recipient,
        subject: job.subject,
        body: job.body,
        attachments: job.attachments,
        timestamp: new Date().toISOString(),
      });
      queueStatus.lastSent.push({
        jobId: job.jobId,
        username: job.username,
        recipient: job.recipient,
        subject: job.subject,
        sentAt: new Date().toISOString(),
        status: 'sent',
      });
      if (queueStatus.lastSent.length > 20) queueStatus.lastSent.shift();
    } catch (error) {
      queueStatus.errors.push({
        jobId: job.jobId,
        username: job.username,
        recipient: job.recipient,
        subject: job.subject,
        error: error.message,
        failedAt: new Date().toISOString(),
      });
      if (queueStatus.errors.length > 20) queueStatus.errors.shift();
    }
    // Remove from processing
    queueStatus.processing = queueStatus.processing.filter(j => j.jobId !== job.jobId);
    processed++;
  }
  updateQueueStatus();
}, 60 * 1000); // Every minute

// Endpoint to send email (now queues jobs)
app.post('/api/send', uploadFields, (req, res) => {
  const { subject, username, password } = req.body;
  const attachments = req.files['attachments'] || [];
  const recipientsFile = req.files['recipients'] ? req.files['recipients'][0] : null;

  // Authenticate user
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    log(`Authentication failed for username: ${username}`, 'ERROR');
    return res.status(401).json({ error: 'Authentication failed' });
  }

  if (!recipientsFile || !subject) {
    const errorMsg = 'Missing required fields';
    log(errorMsg, 'ERROR');
    [...attachments, ...(recipientsFile ? [recipientsFile] : [])].forEach(file => {
      try { fs.unlink(file.path, () => {}); } catch (err) { log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR'); }
    });
    return res.status(400).json({ error: errorMsg });
  }

  if (path.extname(recipientsFile.originalname).toLowerCase() !== '.csv') {
    log(`Invalid file type for recipients: ${recipientsFile.originalname}`, 'ERROR');
    [...attachments, recipientsFile].forEach(file => {
      try { fs.unlink(file.path, () => {}); } catch (err) { log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR'); }
    });
    return res.status(400).json({ error: 'Recipients file must be a CSV' });
  }

  // Parse recipients CSV
  fs.readFile(recipientsFile.path, 'utf8', async (err, data) => {
    if (err) {
      log(`Failed to read recipients CSV: ${err.message}`, 'ERROR');
      [...attachments, recipientsFile].forEach(file => {
        try { fs.unlink(file.path, () => {}); } catch (err) { log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR'); }
      });
      return res.status(500).json({ error: 'Failed to read recipients CSV' });
    }
    let records = [];
    try {
      records = parse(data, { skip_empty_lines: true });
    } catch (e) {
      log(`Invalid CSV format: ${e.message}`, 'ERROR');
      [...attachments, recipientsFile].forEach(file => {
        try { fs.unlink(file.path, () => {}); } catch (err) { log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR'); }
      });
      return res.status(400).json({ error: 'Invalid CSV format' });
    }
    if (records.length === 0) {
      log('No recipients found in CSV', 'ERROR');
      [...attachments, recipientsFile].forEach(file => {
        try { fs.unlink(file.path, () => {}); } catch (err) { log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR'); }
      });
      return res.status(400).json({ error: 'No recipients found in CSV' });
    }

    // Read the DOCX template
    let templateText;
    try {
      const result = await mammoth.extractRawText({ path: './emailTemplate.docx' });
      templateText = result.value;
      log('Loaded email template successfully.');
    } catch (e) {
      log(`Failed to read email template: ${e.message}`, 'ERROR');
      return res.status(500).json({ error: 'Failed to read email template' });
    }

    // Enqueue each email job
    const enqueuedAt = new Date().toISOString();
    for (let i = 0; i < records.length; i++) {
      const row = records[i];
      const [firstName, lastName, email] = row;
      if (!email) continue;
      const personalizedBody = templateText.replace(/Dear Colleague/g, `Dear ${firstName} ${lastName}`);
      const mailOptions = {
        from: 'mohamed.farag@seu-mail.cairo-code.site',
        to: email,
        subject: subject,
        text: personalizedBody,
        attachments: attachments.map(file => ({ filename: file.originalname, path: file.path })),
      };
      const job = {
        jobId: jobIdCounter++,
        username,
        recipient: email,
        subject,
        body: personalizedBody,
        attachments,
        mailOptions,
        enqueuedAt,
      };
      emailQueue.push(job);
    }
    updateQueueStatus();
    // Clean up uploaded files (after enqueuing)
    [...attachments, recipientsFile].forEach(file => {
      try { fs.unlink(file.path, () => {}); } catch (err) { log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR'); }
    });
    log(`Enqueued ${records.length} emails for user ${username}`);
    res.json({ success: true, enqueued: records.length });
  });
});

// === QUEUE STATUS ENDPOINT ===
app.get('/api/queue', (req, res) => {
  res.json({
    pending: queueStatus.pending,
    processing: queueStatus.processing,
    lastSent: queueStatus.lastSent,
    errors: queueStatus.errors,
    queueLength: emailQueue.length,
  });
});

// API: get archived emails
app.post('/api/archived-emails', express.json(), (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    log(`Archive access denied for username: ${username}`, 'ERROR');
    return res.status(401).json({ error: 'Authentication failed' });
  }
  try {
    const archiveFile = './logs/sent_emails_archive.json';
    if (!fs.existsSync(archiveFile)) {
      return res.json({ emails: [] });
    }
    const archives = JSON.parse(fs.readFileSync(archiveFile, 'utf8'));
    const userArchives = archives.filter(email => email.username === username);
    res.json({ emails: userArchives });
  } catch (e) {
    log(`Failed to read email archives: ${e.message}`, 'ERROR');
    res.status(500).json({ error: 'Failed to read archives' });
  }
});

// Start servers
httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  log(`HTTP/WS Server running on port ${HTTP_PORT} (IPv4)`);
  log(`WARNING: Running HTTP server allows insecure connections.`, 'WARNING');
});

httpServer.listen(HTTP_PORT, '::', () => {
  log(`HTTP/WS Server running on port ${HTTP_PORT} (IPv6)`);
});

if (useHttps) {
  httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
    log(`HTTPS/WSS Server running on port ${HTTPS_PORT} (IPv4)`);
  });
  httpsServer.listen(HTTPS_PORT, '::', () => {
    log(`HTTPS/WSS Server running on port ${HTTPS_PORT} (IPv6)`);
  });
}
