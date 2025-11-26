import { useState } from 'react';
import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { 
  Search, Mail, Phone, Globe, Shield, FileImage, Hash, ScanLine,
  ArrowLeft, Loader2, ExternalLink, CheckCircle2, XCircle, AlertCircle
} from 'lucide-react';
import './App.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// ============= HOME PAGE =============

const HomePage = () => {
  const navigate = useNavigate();

  const tools = [
    {
      id: 'username',
      title: 'Username Analyzer',
      description: 'Find social media profiles for a specific username across hundreds of platforms.',
      icon: Search,
      gradient: 'from-cyan-500 to-blue-500',
      path: '/tool/username'
    },
    {
      id: 'email',
      title: 'Email Analyzer',
      description: 'Analyze an email to verify its existence, reputation, and online presence.',
      icon: Mail,
      gradient: 'from-purple-500 to-pink-500',
      path: '/tool/email'
    },
    {
      id: 'phone',
      title: 'Phone Analyzer',
      description: 'Gather information about a phone number, including line type and country.',
      icon: Phone,
      gradient: 'from-green-500 to-emerald-500',
      path: '/tool/phone'
    },
    {
      id: 'domain',
      title: 'Domain Analyzer',
      description: 'Collect WHOIS data, DNS records, and validated subdomains for a domain.',
      icon: Globe,
      gradient: 'from-orange-500 to-red-500',
      path: '/tool/domain'
    },
    {
      id: 'port',
      title: 'Port Scanner',
      description: 'Scan an IP or domain to discover open ports and the services running on them.',
      icon: ScanLine,
      gradient: 'from-indigo-500 to-purple-500',
      path: '/tool/port'
    },
    {
      id: 'reputation',
      title: 'Reputation Checker',
      description: 'Check IP/domain reputation against CTI sources.',
      icon: Shield,
      gradient: 'from-red-500 to-rose-500',
      path: '/tool/reputation'
    },
    {
      id: 'metadata',
      title: 'Metadata Extractor',
      description: 'Extract hidden EXIF data from images, such as location and camera details.',
      icon: FileImage,
      gradient: 'from-teal-500 to-cyan-500',
      path: '/tool/metadata'
    },
    {
      id: 'hash',
      title: 'Hash Analyzer',
      description: 'Identify the type of a given hash and provide cracking resources for it.',
      icon: Hash,
      gradient: 'from-yellow-500 to-orange-500',
      path: '/tool/hash'
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <h1 className="text-6xl font-bold text-white mb-4" data-testid="hero-title">
            OSINT UI
          </h1>
          <p className="text-xl text-purple-200 mb-8" data-testid="hero-description">
            Professional Open Source Intelligence Platform
          </p>
          <div className="flex gap-4 justify-center">
            <button 
              className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded-lg font-semibold hover:scale-105 transition-transform"
              data-testid="launch-environment-btn"
            >
              Launch OSINT Environment
            </button>
            <button 
              className="px-8 py-3 bg-white/10 text-white rounded-lg font-semibold hover:bg-white/20 transition-colors backdrop-blur-sm"
              data-testid="hacking-courses-btn"
            >
              Hacking Courses
            </button>
          </div>
        </div>

        {/* Tools Grid */}
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-8 text-center" data-testid="tools-section-title">Available Tools</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {tools.map((tool) => {
              const Icon = tool.icon;
              return (
                <div
                  key={tool.id}
                  onClick={() => navigate(tool.path)}
                  className="bg-white/5 backdrop-blur-sm rounded-xl p-6 hover:bg-white/10 transition-all cursor-pointer border border-white/10 hover:scale-105 hover:border-white/20"
                  data-testid={`tool-card-${tool.id}`}
                >
                  <div className={`w-12 h-12 rounded-lg bg-gradient-to-r ${tool.gradient} flex items-center justify-center mb-4`}>
                    <Icon className="w-6 h-6 text-white" />
                  </div>
                  <h3 className="text-xl font-semibold text-white mb-2">{tool.title}</h3>
                  <p className="text-purple-200 text-sm">{tool.description}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

// ============= USERNAME ANALYZER =============

const UsernameAnalyzer = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleAnalyze = async () => {
    if (!username.trim()) return;
    setLoading(true);
    try {
      const response = await axios.post(`${API}/analyze/username`, { username });
      setResults(response.data);
    } catch (error) {
      console.error(error);
      alert('Error analyzing username');
    }
    setLoading(false);
  };

  return (
    <ToolLayout title="Username Analyzer" icon={Search} gradient="from-cyan-500 to-blue-500" onBack={() => navigate('/')}>
      <div className="space-y-6">
        <div className="flex gap-4">
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username to search..."
            className="flex-1 px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-purple-300 focus:outline-none focus:border-cyan-500"
            data-testid="username-input"
          />
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded-lg font-semibold hover:scale-105 transition-transform disabled:opacity-50"
            data-testid="analyze-username-btn"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Analyze'}
          </button>
        </div>

        {results && (
          <div className="space-y-4" data-testid="username-results">
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <h3 className="text-lg font-semibold text-white mb-2">Summary</h3>
              <p className="text-purple-200">Found on {results.found_on} out of {results.total_platforms} platforms</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {results.results.map((result, idx) => (
                <div key={idx} className="bg-white/5 rounded-lg p-4 border border-white/10 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {result.exists ? (
                      <CheckCircle2 className="w-5 h-5 text-green-400" />
                    ) : (
                      <XCircle className="w-5 h-5 text-red-400" />
                    )}
                    <span className="text-white font-medium">{result.platform}</span>
                  </div>
                  {result.exists && (
                    <a href={result.url} target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:text-cyan-300">
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </ToolLayout>
  );
};

// ============= EMAIL ANALYZER =============

const EmailAnalyzer = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleAnalyze = async () => {
    if (!email.trim()) return;
    setLoading(true);
    try {
      const response = await axios.post(`${API}/analyze/email`, { email });
      setResults(response.data);
    } catch (error) {
      console.error(error);
      alert(error.response?.data?.detail || 'Error analyzing email');
    }
    setLoading(false);
  };

  return (
    <ToolLayout title="Email Analyzer" icon={Mail} gradient="from-purple-500 to-pink-500" onBack={() => navigate('/')}>
      <div className="space-y-6">
        <div className="flex gap-4">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter email address..."
            className="flex-1 px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-purple-300 focus:outline-none focus:border-purple-500"
            data-testid="email-input"
          />
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="px-8 py-3 bg-gradient-to-r from-purple-500 to-pink-500 text-white rounded-lg font-semibold hover:scale-105 transition-transform disabled:opacity-50"
            data-testid="analyze-email-btn"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Analyze'}
          </button>
        </div>

        {results && (
          <div className="space-y-4" data-testid="email-results">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <InfoCard label="Status" value={results.status} />
              <InfoCard label="Score" value={`${results.score}/100`} />
              <InfoCard label="Disposable" value={results.disposable ? 'Yes' : 'No'} />
              <InfoCard label="Webmail" value={results.webmail ? 'Yes' : 'No'} />
            </div>
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <h3 className="text-lg font-semibold text-white mb-3">Verification Checks</h3>
              <div className="grid grid-cols-2 gap-2">
                <CheckItem label="Regex Valid" checked={results.regexp} />
                <CheckItem label="MX Records" checked={results.mx_records} />
                <CheckItem label="SMTP Server" checked={results.smtp_server} />
                <CheckItem label="SMTP Check" checked={results.smtp_check} />
              </div>
            </div>
          </div>
        )}
      </div>
    </ToolLayout>
  );
};

// ============= PHONE ANALYZER =============

const PhoneAnalyzer = () => {
  const navigate = useNavigate();
  const [phone, setPhone] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleAnalyze = async () => {
    if (!phone.trim()) return;
    setLoading(true);
    try {
      const response = await axios.post(`${API}/analyze/phone`, { phone });
      setResults(response.data);
    } catch (error) {
      console.error(error);
      alert('Error analyzing phone number');
    }
    setLoading(false);
  };

  return (
    <ToolLayout title="Phone Analyzer" icon={Phone} gradient="from-green-500 to-emerald-500" onBack={() => navigate('/')}>
      <div className="space-y-6">
        <div className="flex gap-4">
          <input
            type="text"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            placeholder="Enter phone number (e.g., +1234567890)..."
            className="flex-1 px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-purple-300 focus:outline-none focus:border-green-500"
            data-testid="phone-input"
          />
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="px-8 py-3 bg-gradient-to-r from-green-500 to-emerald-500 text-white rounded-lg font-semibold hover:scale-105 transition-transform disabled:opacity-50"
            data-testid="analyze-phone-btn"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Analyze'}
          </button>
        </div>

        {results && results.valid && (
          <div className="space-y-4" data-testid="phone-results">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <InfoCard label="Country" value={results.country_name} />
              <InfoCard label="Carrier" value={results.carrier} />
              <InfoCard label="Line Type" value={results.line_type} />
            </div>
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <h3 className="text-lg font-semibold text-white mb-3">Number Details</h3>
              <div className="space-y-2 text-purple-200">
                <p><span className="font-medium">Local Format:</span> {results.local_format}</p>
                <p><span className="font-medium">International:</span> {results.international_format}</p>
                <p><span className="font-medium">Country Code:</span> {results.country_code}</p>
              </div>
            </div>
          </div>
        )}
        {results && !results.valid && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
            <p className="text-red-400">{results.error || 'Invalid phone number'}</p>
          </div>
        )}
      </div>
    </ToolLayout>
  );
};

// ============= DOMAIN ANALYZER =============

const DomainAnalyzer = () => {
  const navigate = useNavigate();
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleAnalyze = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    try {
      const response = await axios.post(`${API}/analyze/domain`, { domain });
      setResults(response.data);
    } catch (error) {
      console.error(error);
      alert('Error analyzing domain');
    }
    setLoading(false);
  };

  return (
    <ToolLayout title="Domain Analyzer" icon={Globe} gradient="from-orange-500 to-red-500" onBack={() => navigate('/')}>
      <div className="space-y-6">
        <div className="flex gap-4">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Enter domain (e.g., example.com)..."
            className="flex-1 px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-purple-300 focus:outline-none focus:border-orange-500"
            data-testid="domain-input"
          />
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="px-8 py-3 bg-gradient-to-r from-orange-500 to-red-500 text-white rounded-lg font-semibold hover:scale-105 transition-transform disabled:opacity-50"
            data-testid="analyze-domain-btn"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Analyze'}
          </button>
        </div>

        {results && (
          <div className="space-y-4" data-testid="domain-results">
            {/* WHOIS Info */}
            {!results.whois.error && (
              <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                <h3 className="text-lg font-semibold text-white mb-3">WHOIS Information</h3>
                <div className="space-y-2 text-purple-200 text-sm">
                  <p><span className="font-medium">Domain:</span> {results.whois.domain_name}</p>
                  <p><span className="font-medium">Registrar:</span> {results.whois.registrar}</p>
                  <p><span className="font-medium">Created:</span> {results.whois.creation_date}</p>
                  <p><span className="font-medium">Expires:</span> {results.whois.expiration_date}</p>
                  {results.whois.org && <p><span className="font-medium">Organization:</span> {results.whois.org}</p>}
                </div>
              </div>
            )}
            
            {/* DNS Records */}
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <h3 className="text-lg font-semibold text-white mb-3">DNS Records</h3>
              <div className="space-y-3">
                {Object.entries(results.dns).map(([type, records]) => (
                  records.length > 0 && (
                    <div key={type}>
                      <p className="text-purple-300 font-medium text-sm mb-1">{type} Records:</p>
                      <div className="space-y-1">
                        {records.map((record, idx) => (
                          <p key={idx} className="text-purple-200 text-sm pl-4">{record}</p>
                        ))}
                      </div>
                    </div>
                  )
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </ToolLayout>
  );
};

// ============= PORT SCANNER =============

const PortScanner = () => {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('21,22,23,25,80,443,3306,3389,8080,8443');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleScan = async () => {
    if (!target.trim()) return;
    setLoading(true);
    try {
      const response = await axios.post(`${API}/scan/ports`, { target, ports });
      setResults(response.data);
    } catch (error) {
      console.error(error);
      alert('Error scanning ports');
    }
    setLoading(false);
  };

  return (
    <ToolLayout title="Port Scanner" icon={ScanLine} gradient="from-indigo-500 to-purple-500" onBack={() => navigate('/')}>
      <div className="space-y-6">
        <div className="space-y-4">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter IP or domain..."
            className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-purple-300 focus:outline-none focus:border-indigo-500"
            data-testid="target-input"
          />
          <input
            type="text"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
            placeholder="Ports (comma separated)..."
            className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-purple-300 focus:outline-none focus:border-indigo-500"
            data-testid="ports-input"
          />
          <button
            onClick={handleScan}
            disabled={loading}
            className="w-full px-8 py-3 bg-gradient-to-r from-indigo-500 to-purple-500 text-white rounded-lg font-semibold hover:scale-105 transition-transform disabled:opacity-50"
            data-testid="scan-ports-btn"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin mx-auto" /> : 'Scan Ports'}
          </button>
        </div>

        {results && (
          <div className="space-y-4" data-testid="port-results">
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <p className="text-purple-200"><span className="font-medium">Target IP:</span> {results.ip}</p>
              <p className="text-purple-200"><span className="font-medium">Open Ports:</span> {results.open_ports}/{results.total_scanned}</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {results.results.map((result, idx) => (
                <div key={idx} className={`rounded-lg p-3 border ${
                  result.status === 'open' 
                    ? 'bg-green-500/10 border-green-500/20' 
                    : 'bg-white/5 border-white/10'
                }`}>
                  <div className="flex items-center justify-between">
                    <span className="text-white font-medium">Port {result.port}</span>
                    <span className={`text-sm ${
                      result.status === 'open' ? 'text-green-400' : 'text-gray-400'
                    }`}>
                      {result.status}
                    </span>
                  </div>
                  <p className="text-purple-200 text-sm mt-1">{result.service}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </ToolLayout>
  );
};

// ============= REPUTATION CHECKER =============

const ReputationChecker = () => {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState('domain');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleCheck = async () => {
    if (!target.trim()) return;
    setLoading(true);
    try {
      const response = await axios.post(`${API}/check/reputation`, { target, target_type: targetType });
      setResults(response.data);
    } catch (error) {
      console.error(error);
      alert('Error checking reputation');
    }
    setLoading(false);
  };

  return (
    <ToolLayout title="Reputation Checker" icon={Shield} gradient="from-red-500 to-rose-500" onBack={() => navigate('/')}>
      <div className="space-y-6">
        <div className="space-y-4">
          <div className="flex gap-4">
            <button
              onClick={() => setTargetType('domain')}
              className={`flex-1 px-4 py-2 rounded-lg font-medium transition-colors ${
                targetType === 'domain' 
                  ? 'bg-red-500 text-white' 
                  : 'bg-white/10 text-purple-200 hover:bg-white/20'
              }`}
              data-testid="type-domain-btn"
            >
              Domain
            </button>
            <button
              onClick={() => setTargetType('ip')}
              className={`flex-1 px-4 py-2 rounded-lg font-medium transition-colors ${
                targetType === 'ip' 
                  ? 'bg-red-500 text-white' 
                  : 'bg-white/10 text-purple-200 hover:bg-white/20'
              }`}
              data-testid="type-ip-btn"
            >
              IP Address
            </button>
          </div>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={`Enter ${targetType}...`}
            className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-purple-300 focus:outline-none focus:border-red-500"
            data-testid="reputation-input"
          />
          <button
            onClick={handleCheck}
            disabled={loading}
            className="w-full px-8 py-3 bg-gradient-to-r from-red-500 to-rose-500 text-white rounded-lg font-semibold hover:scale-105 transition-transform disabled:opacity-50"
            data-testid="check-reputation-btn"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin mx-auto" /> : 'Check Reputation'}
          </button>
        </div>

        {results && (
          <div className="space-y-4" data-testid="reputation-results">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <InfoCard label="Malicious" value={results.malicious} color="text-red-400" />
              <InfoCard label="Suspicious" value={results.suspicious} color="text-yellow-400" />
              <InfoCard label="Harmless" value={results.harmless} color="text-green-400" />
              <InfoCard label="Undetected" value={results.undetected} color="text-gray-400" />
            </div>
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <h3 className="text-lg font-semibold text-white mb-3">Analysis Summary</h3>
              <div className="space-y-2 text-purple-200">
                <p><span className="font-medium">Reputation Score:</span> {results.reputation}</p>
                <p><span className="font-medium">Community Votes (Harmless):</span> {results.total_votes.harmless}</p>
                <p><span className="font-medium">Community Votes (Malicious):</span> {results.total_votes.malicious}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </ToolLayout>
  );
};

// ============= METADATA EXTRACTOR =============

const MetadataExtractor = () => {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleExtract = async () => {
    if (!file) return;
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const response = await axios.post(`${API}/extract/metadata`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResults(response.data);
    } catch (error) {
      console.error(error);
      alert('Error extracting metadata');
    }
    setLoading(false);
  };

  return (
    <ToolLayout title="Metadata Extractor" icon={FileImage} gradient="from-teal-500 to-cyan-500" onBack={() => navigate('/')}>
      <div className="space-y-6">
        <div className="space-y-4">
          <div className="border-2 border-dashed border-white/20 rounded-lg p-8 text-center">
            <input
              type="file"
              accept="image/*"
              onChange={(e) => setFile(e.target.files[0])}
              className="hidden"
              id="file-upload"
              data-testid="file-input"
            />
            <label htmlFor="file-upload" className="cursor-pointer">
              <FileImage className="w-12 h-12 mx-auto text-purple-300 mb-3" />
              <p className="text-white font-medium">{file ? file.name : 'Click to select an image'}</p>
              <p className="text-purple-300 text-sm mt-1">JPG, PNG, or other image formats</p>
            </label>
          </div>
          <button
            onClick={handleExtract}
            disabled={!file || loading}
            className="w-full px-8 py-3 bg-gradient-to-r from-teal-500 to-cyan-500 text-white rounded-lg font-semibold hover:scale-105 transition-transform disabled:opacity-50"
            data-testid="extract-metadata-btn"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin mx-auto" /> : 'Extract Metadata'}
          </button>
        </div>

        {results && (
          <div className="space-y-4" data-testid="metadata-results">
            {results.basic_info && !results.basic_info.error && (
              <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                <h3 className="text-lg font-semibold text-white mb-3">Basic Information</h3>
                <div className="grid grid-cols-2 gap-2 text-sm text-purple-200">
                  <p><span className="font-medium">Format:</span> {results.basic_info.format}</p>
                  <p><span className="font-medium">Size:</span> {results.basic_info.width} x {results.basic_info.height}</p>
                  <p><span className="font-medium">Mode:</span> {results.basic_info.mode}</p>
                </div>
              </div>
            )}
            {results.detailed_exif && Object.keys(results.detailed_exif).length > 0 && (
              <div className="bg-white/5 rounded-lg p-4 border border-white/10 max-h-96 overflow-y-auto">
                <h3 className="text-lg font-semibold text-white mb-3">EXIF Data</h3>
                <div className="space-y-1 text-sm">
                  {Object.entries(results.detailed_exif).map(([key, value]) => (
                    <p key={key} className="text-purple-200">
                      <span className="font-medium">{key}:</span> {value}
                    </p>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </ToolLayout>
  );
};

// ============= HASH ANALYZER =============

const HashAnalyzer = () => {
  const navigate = useNavigate();
  const [hash, setHash] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const handleAnalyze = async () => {
    if (!hash.trim()) return;
    setLoading(true);
    try {
      const response = await axios.post(`${API}/analyze/hash`, { hash_value: hash });
      setResults(response.data);
    } catch (error) {
      console.error(error);
      alert('Error analyzing hash');
    }
    setLoading(false);
  };

  return (
    <ToolLayout title="Hash Analyzer" icon={Hash} gradient="from-yellow-500 to-orange-500" onBack={() => navigate('/')}>
      <div className="space-y-6">
        <div className="flex gap-4">
          <input
            type="text"
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            placeholder="Enter hash value..."
            className="flex-1 px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-purple-300 focus:outline-none focus:border-yellow-500 font-mono"
            data-testid="hash-input"
          />
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="px-8 py-3 bg-gradient-to-r from-yellow-500 to-orange-500 text-white rounded-lg font-semibold hover:scale-105 transition-transform disabled:opacity-50"
            data-testid="analyze-hash-btn"
          >
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Analyze'}
          </button>
        </div>

        {results && (
          <div className="space-y-4" data-testid="hash-results">
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <h3 className="text-lg font-semibold text-white mb-3">Hash Analysis</h3>
              <div className="space-y-2 text-purple-200">
                <p><span className="font-medium">Length:</span> {results.length} characters</p>
                <p><span className="font-medium">Possible Types:</span> {results.possible_types.join(', ')}</p>
              </div>
            </div>
            <div className="bg-white/5 rounded-lg p-4 border border-white/10">
              <h3 className="text-lg font-semibold text-white mb-3">Cracking Resources</h3>
              <div className="space-y-2">
                {results.cracking_resources.map((resource, idx) => (
                  <a
                    key={idx}
                    href={resource.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-between p-3 bg-white/5 rounded-lg hover:bg-white/10 transition-colors"
                  >
                    <span className="text-white font-medium">{resource.name}</span>
                    <ExternalLink className="w-4 h-4 text-purple-300" />
                  </a>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </ToolLayout>
  );
};

// ============= UTILITY COMPONENTS =============

const ToolLayout = ({ children, title, icon: Icon, gradient, onBack }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="container mx-auto px-4 py-8">
        <button
          onClick={onBack}
          className="flex items-center gap-2 text-purple-200 hover:text-white mb-6 transition-colors"
          data-testid="back-button"
        >
          <ArrowLeft className="w-5 h-5" />
          Back to Tools
        </button>
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center gap-4 mb-8">
            <div className={`w-16 h-16 rounded-xl bg-gradient-to-r ${gradient} flex items-center justify-center`}>
              <Icon className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-4xl font-bold text-white">{title}</h1>
          </div>
          {children}
        </div>
      </div>
    </div>
  );
};

const InfoCard = ({ label, value, color = 'text-white' }) => (
  <div className="bg-white/5 rounded-lg p-4 border border-white/10">
    <p className="text-purple-300 text-sm mb-1">{label}</p>
    <p className={`font-semibold text-lg ${color}`}>{value}</p>
  </div>
);

const CheckItem = ({ label, checked }) => (
  <div className="flex items-center gap-2">
    {checked ? (
      <CheckCircle2 className="w-4 h-4 text-green-400" />
    ) : (
      <XCircle className="w-4 h-4 text-red-400" />
    )}
    <span className="text-purple-200 text-sm">{label}</span>
  </div>
);

// ============= MAIN APP =============

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/tool/username" element={<UsernameAnalyzer />} />
        <Route path="/tool/email" element={<EmailAnalyzer />} />
        <Route path="/tool/phone" element={<PhoneAnalyzer />} />
        <Route path="/tool/domain" element={<DomainAnalyzer />} />
        <Route path="/tool/port" element={<PortScanner />} />
        <Route path="/tool/reputation" element={<ReputationChecker />} />
        <Route path="/tool/metadata" element={<MetadataExtractor />} />
        <Route path="/tool/hash" element={<HashAnalyzer />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;