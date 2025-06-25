import React, { useState, useEffect } from 'react';
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'

function App() {
  const [serverIp, setServerIp] = useState(localStorage.getItem('serverIp') || '');
  const [showIpPrompt, setShowIpPrompt] = useState(!serverIp);
  const [form, setForm] = useState({ subject: '', text: '' });
  const [attachments, setAttachments] = useState([]);
  const [csvFile, setCsvFile] = useState(null);
  const [status, setStatus] = useState('');

  useEffect(() => {
    if (!serverIp) setShowIpPrompt(true);
  }, [serverIp]);

  const handleChange = e => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleFileChange = e => {
    setAttachments(Array.from(e.target.files).slice(0, 2));
  };

  const handleCsvChange = e => {
    setCsvFile(e.target.files[0] || null);
  };

  const handleSubmit = async e => {
    e.preventDefault();
    setStatus('Sending...');
    const formData = new FormData();
    formData.append('subject', form.subject);
    formData.append('text', form.text);
    if (csvFile) formData.append('recipients', csvFile);
    attachments.forEach(file => formData.append('attachments', file));
    try {
      const res = await fetch(`http://${serverIp}:3001/api/send`, {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (data.success) setStatus('Email sent!');
      else setStatus(data.error || 'Failed to send email');
    } catch (err) {
      setStatus('Failed to send email');
    }
  };

  const handleIpSubmit = e => {
    e.preventDefault();
    if (serverIp) {
      localStorage.setItem('serverIp', serverIp);
      setShowIpPrompt(false);
    }
  };

  const handleIpChange = e => {
    setServerIp(e.target.value);
  };

  const handleChangeIp = () => {
    setShowIpPrompt(true);
  };

  if (showIpPrompt) {
    return (
      <div style={{ maxWidth: 400, margin: '4rem auto', fontFamily: 'sans-serif' }}>
        <h2>Enter Backend Server IP Address</h2>
        <form onSubmit={handleIpSubmit}>
          <input
            type="text"
            value={serverIp}
            onChange={handleIpChange}
            placeholder="e.g. 192.168.1.100"
            required
            style={{ width: '100%', padding: 8, fontSize: 16 }}
          />
          <button type="submit" style={{ marginTop: 16 }}>Save</button>
        </form>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 600, margin: '2rem auto', fontFamily: 'sans-serif' }}>
      <button onClick={handleChangeIp} style={{ float: 'right' }}>Change Server IP</button>
      <h1>Send Email</h1>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Recipients CSV:</label>
          <input type="file" accept=".csv" onChange={handleCsvChange} required />
        </div>
        <div>
          <label>Subject:</label>
          <input name="subject" value={form.subject} onChange={handleChange} required />
        </div>
        <div>
          <label>Body:</label>
          <textarea name="text" value={form.text} onChange={handleChange} required />
        </div>
        <div>
          <label>Attachments (max 2):</label>
          <input type="file" multiple onChange={handleFileChange} accept="*" />
        </div>
        <button type="submit">Send</button>
      </form>
      <div style={{ marginTop: 20, color: 'green' }}>{status}</div>
    </div>
  );
}

export default App
