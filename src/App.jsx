import React, { useEffect, useState } from 'react';
import './App.css';

// API Configuration
const DEFAULT_SERVER = '89.168.74.94';
const HTTP_PORT = 80;
const HTTPS_PORT = 443;

const TABS = {
  SEND: 'Send Email',
  SENT: 'Sent Emails',
  ARCHIVES: 'Email Archives'
};

const App = () => {
  const [logs, setLogs] = useState([]);
  const [wsStatus, setWsStatus] = useState('disconnected');
  const [connectionProtocol, setConnectionProtocol] = useState('https');
  const [wsProtocol, setWsProtocol] = useState('wss');
  const [serverAddress, setServerAddress] = useState(DEFAULT_SERVER);
  const [emails, setEmails] = useState([]);
  const [subject, setSubject] = useState('');
  const [attachments, setAttachments] = useState(null);
  const [recipientsFile, setRecipientsFile] = useState(null);
  const [previewRecipients, setPreviewRecipients] = useState([]);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [username, setUsername] = useState(localStorage.getItem('username') || '');
  const [password, setPassword] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('username'));
  const [activeTab, setActiveTab] = useState(TABS.SEND);
  const [sentEmails, setSentEmails] = useState([]);
  const [loadingSent, setLoadingSent] = useState(false);
  const [loginLoading, setLoginLoading] = useState(false);
  const [archivedEmails, setArchivedEmails] = useState([]);
  const [loadingArchives, setLoadingArchives] = useState(false);
  const [expandedEmail, setExpandedEmail] = useState(null);
  const [showConfig, setShowConfig] = useState(false);

  // Dynamic URLs
  const getApiUrl = () => `${connectionProtocol}://${serverAddress}:${connectionProtocol === 'https' ? HTTPS_PORT : HTTP_PORT}`;
  const getWsUrl = () => `${wsProtocol}://${serverAddress}:${wsProtocol === 'wss' ? HTTPS_PORT : HTTP_PORT}`;

  // Logging function
  const log = (message, level = 'INFO') => {
    const timestamp = new Date().toISOString();
    const formattedMessage = `[${timestamp}] ${level}: ${message}`;
    console.log(formattedMessage);
    setLogs(prev => [...prev, formattedMessage]);
  };

  // Fetch email list
  const fetchEmails = async (protocol = 'https') => {
    const url = `${protocol}://${serverAddress}:${protocol === 'https' ? HTTPS_PORT : HTTP_PORT}/api/emails`;
    log(`Fetching email list from ${url}`);
    try {
      const res = await fetch(url);
      const data = await res.json();
      if (data.error) {
        log(`Failed to fetch email list: ${data.error}`, 'ERROR');
        throw new Error(data.error);
      }
      setEmails(data.emails);
      log(`Fetched ${data.emails.length} emails`);
      setConnectionProtocol(protocol);
      setError('');
    } catch (err) {
      if (protocol === 'https') {
        log('HTTPS failed, falling back to HTTP', 'WARNING');
        setConnectionProtocol('http');
        return fetchEmails('http');
      }
      log(`Error fetching email list: ${err.message}`, 'ERROR');
      setError('Failed to load email list');
    }
  };

  useEffect(() => {
    fetchEmails();
  }, [serverAddress]);

  // WebSocket connection
  useEffect(() => {
    let ws;
    const connectWebSocket = (protocol = 'wss') => {
      const url = `${protocol}://${serverAddress}:${protocol === 'wss' ? HTTPS_PORT : HTTP_PORT}`;
      log(`Attempting to connect to WebSocket at ${url}`);
      ws = new WebSocket(url);

      ws.onopen = () => {
        log(`WebSocket connection established via ${protocol}`);
        setWsStatus('connected');
        setWsProtocol(protocol);
        if (protocol === 'ws') {
          setError('Using insecure WebSocket (WS). Data may be unencrypted.');
        }
      };

      ws.onmessage = (event) => {
        try {
          const message = event.data;
          log(`Received WebSocket message: ${message}`);
        } catch (err) {
          log(`Error processing WebSocket message: ${err.message}`, 'ERROR');
        }
      };

      ws.onerror = (error) => {
        log(`WebSocket error: ${error.message || 'Unknown error'}`, 'ERROR');
        setWsStatus('error');
      };

      ws.onclose = (event) => {
        log(`WebSocket closed (code: ${event.code}, reason: ${event.reason || 'none'})`, 'INFO');
        setWsStatus('disconnected');
        if (protocol === 'wss') {
          log('WSS failed, falling back to WS', 'WARNING');
          setTimeout(() => connectWebSocket('ws'), 5000);
        } else {
          setTimeout(() => connectWebSocket('wss'), 5000);
        }
      };
    };

    connectWebSocket();

    return () => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        log('Closing WebSocket connection');
        ws.close();
      }
    };
  }, [serverAddress]);

  // Handle login
  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoginLoading(true);
    try {
      const res = await fetch(`${getApiUrl()}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (data.error) {
        setError(data.error);
        setLoginLoading(false);
        return;
      }
      setIsLoggedIn(true);
      localStorage.setItem('username', username);
      setError('');
      setSuccess('Logged in successfully!');
      setLoginLoading(false);
    } catch (err) {
      if (connectionProtocol === 'https') {
        log('HTTPS login failed, falling back to HTTP', 'WARNING');
        setConnectionProtocol('http');
        handleLogin(e);
      } else {
        setError('Failed to login');
        setLoginLoading(false);
      }
    }
  };

  // Handle logout
  const handleLogout = () => {
    setIsLoggedIn(false);
    setUsername('');
    setPassword('');
    localStorage.removeItem('username');
    setSuccess('Logged out successfully');
  };

  // Handle form submission
  const handleSendEmail = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (!subject || !recipientsFile) {
      log('Missing required fields for sending email', 'ERROR');
      setError('Please provide subject and recipients CSV');
      return;
    }
    const formData = new FormData();
    formData.append('subject', subject);
    formData.append('recipients', recipientsFile);
    formData.append('username', username);
    formData.append('password', password);
    if (attachments) {
      Array.from(attachments).forEach(file => formData.append('attachments', file));
    }
    log('Sending email');
    try {
      const res = await fetch(`${getApiUrl()}/api/send`, {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (data.error) {
        log(`Failed to send email: ${data.error}`, 'ERROR');
        setError(data.error);
        return;
      }
      log('Email sent successfully');
      setSuccess('Email sent successfully');
      setSubject('');
      setAttachments(null);
      setRecipientsFile(null);
      setPreviewRecipients([]);
      e.target.reset();
    } catch (err) {
      if (connectionProtocol === 'https') {
        log('HTTPS send failed, falling back to HTTP', 'WARNING');
        setConnectionProtocol('http');
        handleSendEmail(e);
      } else {
        log(`Error sending email: ${err.message}`, 'ERROR');
        setError('Failed to send email');
      }
    }
  };

  // Handle recipients CSV preview
  const handlePreview = async () => {
    if (!recipientsFile) {
      log('No recipients CSV selected for preview', 'ERROR');
      setError('Please select a recipients CSV file');
      return;
    }
    const formData = new FormData();
    formData.append('recipients', recipientsFile);
    log('Previewing recipients CSV');
    try {
      const res = await fetch(`${getApiUrl()}/api/preview`, {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (data.error) {
        log(`Failed to preview recipients: ${data.error}`, 'ERROR');
        setError(data.error);
        setPreviewRecipients([]);
        return;
      }
      log(`Previewed ${data.recipients.length} recipients`);
      setPreviewRecipients(data.recipients);
      setError('');
    } catch (err) {
      if (connectionProtocol === 'https') {
        log('HTTPS preview failed, falling back to HTTP', 'WARNING');
        setConnectionProtocol('http');
        handlePreview();
      } else {
        log(`Error previewing recipients: ${err.message}`, 'ERROR');
        setError('Failed to preview recipients');
        setPreviewRecipients([]);
      }
    }
  };

  // Fetch sent emails
  const fetchSentEmails = async () => {
    setLoadingSent(true);
    setError('');
    try {
      const res = await fetch(`${getApiUrl()}/api/sent-emails`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (data.error) {
        setError(data.error);
        setSentEmails([]);
        setLoadingSent(false);
        return;
      }
      setSentEmails(data.emails);
      setLoadingSent(false);
    } catch (err) {
      if (connectionProtocol === 'https') {
        log('HTTPS sent-emails failed, falling back to HTTP', 'WARNING');
        setConnectionProtocol('http');
        fetchSentEmails();
      } else {
        setError('Failed to fetch sent emails');
        setSentEmails([]);
        setLoadingSent(false);
      }
    }
  };

  // Fetch archived emails
  const fetchArchivedEmails = async () => {
    setLoadingArchives(true);
    setError('');
    try {
      const res = await fetch(`${getApiUrl()}/api/archived-emails`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (data.error) {
        setError(data.error);
        setArchivedEmails([]);
        setLoadingArchives(false);
        return;
      }
      setArchivedEmails(data.emails);
      setLoadingArchives(false);
    } catch (err) {
      if (connectionProtocol === 'https') {
        log('HTTPS archived-emails failed, falling back to HTTP', 'WARNING');
        setConnectionProtocol('http');
        fetchArchivedEmails();
      } else {
        setError('Failed to fetch archived emails');
        setArchivedEmails([]);
        setLoadingArchives(false);
      }
    }
  };

  useEffect(() => {
    if (isLoggedIn && activeTab === TABS.SENT) {
      fetchSentEmails();
    }
    if (isLoggedIn && activeTab === TABS.ARCHIVES) {
      fetchArchivedEmails();
    }
  }, [isLoggedIn, activeTab, connectionProtocol, serverAddress]);

  // Handle server address change
  const handleServerChange = (e) => {
    e.preventDefault();
    const newAddress = e.target.elements.serverAddress.value;
    setServerAddress(newAddress);
    setShowConfig(false);
    log(`Server address updated to ${newAddress}`);
    fetchEmails('https'); // Retry with new address
  };

  // UI
  if (!isLoggedIn) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-100 to-blue-300">
        <form onSubmit={handleLogin} className="bg-white shadow-lg rounded-lg p-8 w-full max-w-sm space-y-6">
          <h2 className="text-2xl font-bold text-center mb-4">Login to Email System</h2>
          <div>
            <label className="block text-sm font-medium">Username</label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              className="mt-1 block w-full border rounded p-2"
              placeholder="Enter your username"
              autoFocus
            />
          </div>
          <div>
            <label className="block text-sm font-medium">Password</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              className="mt-1 block w-full border rounded p-2"
              placeholder="Enter your password"
            />
          </div>
          {error && <p className="text-red-500 text-center">{error}</p>}
          {success && <p className="text-green-500 text-center">{success}</p>}
          <button
            type="submit"
            className="w-full bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:opacity-50"
            disabled={loginLoading}
          >
            {loginLoading ? 'Logging in...' : 'Login'}
          </button>
          <button
            type="button"
            onClick={() => setShowConfig(true)}
            className="w-full bg-gray-400 text-white px-4 py-2 rounded hover:bg-gray-600 mt-2"
          >
            Configure Server
          </button>
          {showConfig && (
            <div className="mt-4">
              <form onSubmit={handleServerChange} className="space-y-2">
                <label className="block text-sm font-medium">Server Address (IPv4/IPv6)</label>
                <input
                  type="text"
                  defaultValue={serverAddress}
                  name="serverAddress"
                  className="mt-1 block w-full border rounded p-2"
                  placeholder="e.g., 89.168.74.94 or [::1]"
                />
                <button
                  type="submit"
                  className="w-full bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
                >
                  Save
                </button>
              </form>
            </div>
          )}
        </form>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-100 to-blue-300 p-4">
      <div className="max-w-2xl mx-auto bg-white rounded-lg shadow-lg p-6 mt-8">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-2xl font-bold">Email Client</h1>
          <div className="flex space-x-4 items-center">
            <span className={`text-sm ${wsStatus === 'connected' ? 'text-green-500' : 'text-red-500'}`}>
              WebSocket: {wsStatus} ({wsProtocol.toUpperCase()})
            </span>
            <span className={`text-sm ${connectionProtocol === 'https' ? 'text-green-500' : 'text-yellow-500'}`}>
              API: {connectionProtocol.toUpperCase()}
            </span>
            <button
              onClick={() => setShowConfig(true)}
              className="bg-gray-400 text-white px-3 py-1 rounded hover:bg-gray-600"
            >
              Config
            </button>
            <button
              onClick={handleLogout}
              className="bg-gray-400 text-white px-3 py-1 rounded hover:bg-gray-600"
            >
              Logout
            </button>
          </div>
        </div>
        {showConfig && (
          <div className="mb-6">
            <form onSubmit={handleServerChange} className="space-y-2">
              <label className="block text-sm font-medium">Server Address (IPv4/IPv6)</label>
              <input
                type="text"
                defaultValue={serverAddress}
                name="serverAddress"
                className="mt-1 block w-full border rounded p-2"
                placeholder="e.g., 89.168.74.94 or [::1]"
              />
              <button
                type="submit"
                className="w-full bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
              >
                Save
              </button>
            </form>
          </div>
        )}
        <div className="flex space-x-4 mb-6">
          <button
            className={`px-4 py-2 rounded ${activeTab === TABS.SEND ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-700'}`}
            onClick={() => setActiveTab(TABS.SEND)}
          >
            Send Email
          </button>
          <button
            className={`px-4 py-2 rounded ${activeTab === TABS.SENT ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-700'}`}
            onClick={() => setActiveTab(TABS.SENT)}
          >
            Sent Emails
          </button>
          <button
            className={`px-4 py-2 rounded ${activeTab === TABS.ARCHIVES ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-700'}`}
            onClick={() => setActiveTab(TABS.ARCHIVES)}
          >
            Archives
          </button>
        </div>
        {activeTab === TABS.SEND && (
          <form onSubmit={handleSendEmail} className="space-y-4">
            <div>
              <label className="block text-sm font-medium">Subject</label>
              <input
                type="text"
                value={subject}
                onChange={e => setSubject(e.target.value)}
                className="mt-1 block w-full border rounded p-2"
                placeholder="Enter email subject"
              />
            </div>
            <div>
              <label className="block text-sm font-medium">Attachments (up to 2)</label>
              <input
                type="file"
                multiple
                onChange={e => setAttachments(e.target.files)}
                className="mt-1 block w-full"
                accept=".pdf,.txt,.doc,.docx"
              />
            </div>
            <div>
              <label className="block text-sm font-medium">Recipients CSV</label>
              <input
                type="file"
                onChange={e => {
                  setRecipientsFile(e.target.files[0]);
                  setPreviewRecipients([]);
                }}
                className="mt-1 block w-full"
                accept=".csv"
              />
              <button
                type="button"
                onClick={handlePreview}
                className="mt-2 bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600"
                disabled={!recipientsFile}
              >
                Preview Recipients
              </button>
            </div>
            {previewRecipients.length > 0 && (
              <div>
                <h3 className="text-lg font-semibold">Preview Recipients</h3>
                <ul className="border rounded p-2 max-h-40 overflow-y-auto">
                  {previewRecipients.map((email, index) => (
                    <li key={index} className="py-1">{email}</li>
                  ))}
                </ul>
              </div>
            )}
            {error && <p className="text-red-500">{error}</p>}
            {success && <p className="text-green-500">{success}</p>}
            {connectionProtocol === 'http' && (
              <p className="text-yellow-500">Warning: Using insecure HTTP connection. Data may be unencrypted.</p>
            )}
            <button
              type="submit"
              className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
            >
              Send Email
            </button>
          </form>
        )}
        {activeTab === TABS.SENT && (
          <div>
            <h3 className="text-lg font-semibold mb-2">Sent Emails</h3>
            {loadingSent ? (
              <p>Loading...</p>
            ) : sentEmails.length === 0 ? (
              <p>No sent emails found.</p>
            ) : (
              <ul className="border rounded p-2 max-h-60 overflow-y-auto bg-gray-50">
                {sentEmails.map((line, idx) => (
                  <li key={idx} className="text-sm font-mono">{line}</li>
                ))}
              </ul>
            )}
            {error && <p className="text-red-500 mt-2">{error}</p>}
          </div>
        )}
        {activeTab === TABS.ARCHIVES && (
          <div>
            <h3 className="text-lg font-semibold mb-2">Email Archives</h3>
            {loadingArchives ? (
              <p>Loading archives...</p>
            ) : archivedEmails.length === 0 ? (
              <p>No archived emails found.</p>
            ) : (
              <div className="space-y-4">
                {archivedEmails.map((email, idx) => (
                  <div key={idx} className="border rounded-lg p-4 bg-gray-50">
                    <div className="flex justify-between items-start">
                      <div>
                        <p className="font-semibold">To: {email.recipient}</p>
                        <p className="text-sm text-gray-600">Subject: {email.subject}</p>
                        <p className="text-xs text-gray-500">
                          Sent: {new Date(email.timestamp).toLocaleString()}
                        </p>
                      </div>
                      <button
                        onClick={() => setExpandedEmail(expandedEmail === idx ? null : idx)}
                        className="text-blue-500 hover:text-blue-700"
                      >
                        {expandedEmail === idx ? 'Hide Details' : 'Show Details'}
                      </button>
                    </div>
                    {expandedEmail === idx && (
                      <div className="mt-4 space-y-2">
                        <div className="bg-white p-3 rounded border">
                          <p className="whitespace-pre-wrap">{email.body}</p>
                        </div>
                        {email.attachments?.length > 0 && (
                          <div>
                            <p className="font-medium">Attachments:</p>
                            <ul className="list-disc list-inside">
                              {email.attachments.map((att, attIdx) => (
                                <li key={attIdx} className="text-sm">
                                  {att.filename}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
            {error && <p className="text-red-500 mt-2">{error}</p>}
          </div>
        )}
        <div className="mt-6">
          <h3 className="text-lg font-semibold mb-2">Server Logs</h3>
          <ul className="border rounded p-2 max-h-60 overflow-y-auto bg-gray-50">
            {logs.map((log, index) => (
              <li key={index} className="py-1 text-sm">{log}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default App;