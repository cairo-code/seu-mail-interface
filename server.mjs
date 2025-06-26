import express from 'express';
import multer from 'multer';
import cors from 'cors';
import fs from 'fs';
import { exec } from 'child_process';
import path from 'path';
import { parse } from 'csv-parse/sync';
import { WebSocketServer, WebSocket } from 'ws';
import mammoth from 'mammoth';
import nodemailer from 'nodemailer';
import http from 'http';

const app = express();
const PORT = 3001;
const upload = multer({ dest: 'uploads/' });

// Configure CORS for Vercel deployment
const corsOptions = {
  origin: [
    'https://seu-mail-interface.vercel.app',
    'https://seu-mail-interface-git-main-freddys-projects.vercel.app',
    'https://seu-mail-interface-freddys-projects.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173'
  ],
  methods: ['GET', 'POST'],
  credentials: true,
  allowedHeaders: ['Content-Type']
};

app.use(cors(corsOptions));

// Enhanced logging: log to file as well as console
const LOG_FILE_PATH = './logs/server.log';
function appendLogToFile(message) {
  try {
    fs.mkdirSync('./logs', { recursive: true });
    fs.appendFileSync(LOG_FILE_PATH, message + '\n');
  } catch (e) {
    // Fallback: log file error
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

// Update multer to accept both attachments and a recipients CSV
const uploadFields = upload.fields([
  { name: 'attachments', maxCount: 2 },
  { name: 'recipients', maxCount: 1 },
]);

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  host: 'smtp.email.eu-frankfurt-1.oci.oraclecloud.com',
  port: 587,
  secure: false, // TLS but not SSL
  auth: {
    user: 'ocid1.user.oc1..aaaaaaaaxiz77zaakub67voy326ftfmhcm23xiifb3rrs22gvkyu2bni5eka@ocid1.tenancy.oc1..aaaaaaaayg4ulvshtq35735jbqjph75pyxmqlzvfm4cajgfii77i2m4i54ba.88.com',
    pass: 'X9qkh&i$kgzK-nlV$}xt',
  },
  tls: {
    rejectUnauthorized: false,
  },
});

// Load users.json synchronously
const users = JSON.parse(fs.readFileSync('./users.json', 'utf8'));

// Start HTTP server only (Nginx will handle HTTPS)
let server;
try {
  server = http.createServer(app).listen(PORT, () => {
    log(`HTTP Server running on http://localhost:${PORT}`);
    log('Production HTTPS is handled by Nginx reverse proxy.');
  });
} catch (err) {
  log(`Failed to start server: ${err.message}`, 'ERROR');
  process.exit(1);
}

// Initialize WebSocket server with origin check
let wss;
try {
  wss = new WebSocketServer({ 
    server,
    verifyClient: ({ origin }) => {
      const allowedOrigins = [
        'https://seu-mail-interface.vercel.app',
        'https://seu-mail-interface-git-main-freddys-projects.vercel.app',
        'https://seu-mail-interface-freddys-projects.vercel.app',
        'http://localhost:3000',
        'http://localhost:5173'
      ];
      return allowedOrigins.includes(origin);
    }
  });
  log('WebSocket server initialized with origin verification');
} catch (err) {
  log(`Failed to initialize WebSocket server: ${err.message}`, 'ERROR');
  process.exit(1);
}

// WebSocket event handlers
wss.on('connection', (ws, req) => {
  log(`New WebSocket client connected from ${req.socket.remoteAddress}`);
  
  ws.on('message', (message) => {
    try {
      const data = message.toString();
      log(`Received WebSocket message: ${data}`);
      broadcastLog(`Client message: ${data}`);
    } catch (err) {
      log(`Error processing WebSocket message: ${err.message}`, 'ERROR');
    }
  });

  ws.on('error', (error) => {
    log(`WebSocket error: ${error.message}`, 'ERROR');
  });

  ws.on('close', (code, reason) => {
    log(`WebSocket client disconnected (code: ${code}, reason: ${reason})`);
  });
});

wss.on('error', (error) => {
  log(`WebSocket server error: ${error.message}`, 'ERROR');
});

// Broadcast function for WebSocket messages
function broadcastLog(message) {
  const timestamp = new Date().toISOString();
  const formattedMessage = `[${timestamp}] ${message}`;
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(formattedMessage);
      } catch (err) {
        log(`Failed to send message to client: ${err.message}`, 'ERROR');
      }
    }
  });
}

// Middleware to log all HTTP requests
app.use(express.json());
app.use((req, res, next) => {
  const logMsg = `HTTP ${req.method} ${req.url} from ${req.ip}`;
  log(logMsg);
  broadcastLog(logMsg);
  next();
});

// Helper: log sent email to global and per-user files
function logSentEmail({ username, recipient, subject }) {
  const timestamp = new Date().toISOString();
  const entry = `${timestamp} | user: ${username} | to: ${recipient} | subject: ${subject}`;
  // Global log
  try {
    fs.mkdirSync('./logs', { recursive: true });
    fs.appendFileSync('./logs/emails_sent.log', entry + '\n');
    fs.appendFileSync(`./logs/sent_${username}.log`, entry + '\n');
  } catch (e) {
    log(`Failed to write sent email log: ${e.message}`, 'ERROR');
  }
}

// Helper: Save complete email content to archive
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

// API: get sent emails for user
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

// Endpoint to send email
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
      try {
        fs.unlink(file.path, () => {});
      } catch (err) {
        log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR');
      }
    });
    return res.status(400).json({ error: errorMsg });
  }

  if (path.extname(recipientsFile.originalname).toLowerCase() !== '.csv') {
    log(`Invalid file type for recipients: ${recipientsFile.originalname}`, 'ERROR');
    [...attachments, recipientsFile].forEach(file => {
      try {
        fs.unlink(file.path, () => {});
      } catch (err) {
        log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR');
      }
    });
    return res.status(400).json({ error: 'Recipients file must be a CSV' });
  }

  // Parse recipients CSV
  fs.readFile(recipientsFile.path, 'utf8', async (err, data) => {
    if (err) {
      log(`Failed to read recipients CSV: ${err.message}`, 'ERROR');
      [...attachments, recipientsFile].forEach(file => {
        try {
          fs.unlink(file.path, () => {});
        } catch (err) {
          log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR');
        }
      });
      return res.status(500).json({ error: 'Failed to read recipients CSV' });
    }
    let records = [];
    try {
      records = parse(data, { skip_empty_lines: true });
    } catch (e) {
      log(`Invalid CSV format: ${e.message}`, 'ERROR');
      [...attachments, recipientsFile].forEach(file => {
        try {
          fs.unlink(file.path, () => {});
        } catch (err) {
          log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR');
        }
      });
      return res.status(400).json({ error: 'Invalid CSV format' });
    }
    if (records.length === 0) {
      log('No recipients found in CSV', 'ERROR');
      [...attachments, recipientsFile].forEach(file => {
        try {
          fs.unlink(file.path, () => {});
        } catch (err) {
          log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR');
        }
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

    // Send personalized email to each recipient
    let sendErrors = [];
    const total = records.length;
    let sentCount = 0;
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
        attachments: attachments.map(file => ({
          filename: file.originalname,
          path: file.path
        })),
      };
      const logMsg = `(${i + 1}/${total}) [User: ${username}] Sending email to: ${email} | Subject: ${subject}`;
      log(logMsg);
      broadcastLog(logMsg);
      try {
        await transporter.sendMail(mailOptions);
        sentCount++;
        logSentEmail({ username, recipient: email, subject });
        // Archive the complete email
        archiveEmail({
          username,
          recipient: email,
          subject,
          body: personalizedBody,
          attachments,
          timestamp: new Date().toISOString()
        });
        const progressMsg = `Progress: ${sentCount}/${total} emails sent by ${username}.`;
        log(progressMsg);
        broadcastLog(progressMsg);
      } catch (error) {
        const errMsg = `Failed to send email to ${email} by ${username}: ${error.message}`;
        log(errMsg, 'ERROR');
        broadcastLog(errMsg);
        sendErrors.push(errMsg);
      }
    }
    // Clean up uploaded files
    [...attachments, recipientsFile].forEach(file => {
      try {
        fs.unlink(file.path, () => {});
      } catch (err) {
        log(`Failed to delete file ${file.path}: ${err.message}`, 'ERROR');
      }
    });
    if (sendErrors.length > 0) {
      log(`Completed with errors. ${sentCount}/${total} emails sent by ${username}.`, 'ERROR');
      return res.status(500).json({ error: sendErrors.join('; ') });
    }
    const successMsg = `All emails sent successfully by ${username}. Total: ${total}`;
    log(successMsg);
    broadcastLog(successMsg);
    res.json({ success: true });
  });
});

// Add new endpoint to retrieve archived emails
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
    // Filter archives for this user if not admin
    const userArchives = archives.filter(email => email.username === username);
    res.json({ emails: userArchives });
  } catch (e) {
    log(`Failed to read email archives: ${e.message}`, 'ERROR');
    res.status(500).json({ error: 'Failed to read archives' });
  }
});