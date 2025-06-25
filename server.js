import express from 'express';
import multer from 'multer';
import cors from 'cors';
import fs from 'fs';
import { exec } from 'child_process';
import path from 'path';
import csvParse from 'csv-parse/lib/sync';

const app = express();
const PORT = 3001;
const upload = multer({ dest: 'uploads/' });

app.use(cors());
app.use(express.json());

// Endpoint to get email list
app.get('/api/emails', (req, res) => {
  fs.readFile('emails.csv', 'utf8', (err, data) => {
    if (err) return res.status(500).json({ error: 'Could not read email list' });
    const lines = data.split(/\r?\n/).filter(Boolean);
    const emails = lines.map(line => {
      const [first, last, email] = line.split(',');
      return { name: `${first} ${last}`.trim(), email: email.trim() };
    });
    res.json({ emails });
  });
});

// Update multer to accept both attachments and a recipients CSV
const uploadFields = upload.fields([
  { name: 'attachments', maxCount: 2 },
  { name: 'recipients', maxCount: 1 },
]);

// Endpoint to send email
app.post('/api/send', uploadFields, (req, res) => {
  const { subject, text } = req.body;
  const attachments = req.files['attachments'] || [];
  const recipientsFile = req.files['recipients'] ? req.files['recipients'][0] : null;

  if (!recipientsFile || !subject || !text) {
    // Clean up uploaded files
    [...attachments, ...(recipientsFile ? [recipientsFile] : [])].forEach(file => fs.unlink(file.path, () => {}));
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Parse recipients CSV
  fs.readFile(recipientsFile.path, 'utf8', (err, data) => {
    if (err) {
      [...attachments, recipientsFile].forEach(file => fs.unlink(file.path, () => {}));
      return res.status(500).json({ error: 'Failed to read recipients CSV' });
    }
    let recipients = [];
    try {
      const records = csvParse(data, { skip_empty_lines: true });
      recipients = records.map(row => row[2]?.trim()).filter(Boolean);
    } catch (e) {
      [...attachments, recipientsFile].forEach(file => fs.unlink(file.path, () => {}));
      return res.status(400).json({ error: 'Invalid CSV format' });
    }
    if (recipients.length === 0) {
      [...attachments, recipientsFile].forEach(file => fs.unlink(file.path, () => {}));
      return res.status(400).json({ error: 'No recipients found in CSV' });
    }
    // Prepare msmtp command
    let cmd = `echo "${text.replace(/"/g, '\"')}" | mail -s "${subject.replace(/"/g, '\"')}"`;
    attachments.forEach(file => {
      cmd += ` -A ${file.path}`;
    });
    cmd += ` ${recipients.join(' ')}`;
    exec(cmd, (error, stdout, stderr) => {
      // Clean up uploaded files
      [...attachments, recipientsFile].forEach(file => fs.unlink(file.path, () => {}));
      if (error) {
        return res.status(500).json({ error: stderr || 'Failed to send email' });
      }
      res.json({ success: true });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
}); 