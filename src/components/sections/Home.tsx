
import React, { useState, useEffect } from 'react';
import StatusCard from '../StatusCard';
import { Cpu, MemoryStick, Activity, Network } from 'lucide-react';

const Home = () => {
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [backendStatus, setBackendStatus] = useState('unknown');

  const fetchMetrics = async () => {
    try {
      console.log('Fetching metrics from backend...');
      const response = await fetch('http://localhost:5000/api/cpu-memory');
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      console.log('Metrics received:', data);
      setMetrics(data);
      setBackendStatus('connected');
    } catch (error) {
      console.error('Error fetching metrics:', error);
      setBackendStatus('disconnected');
    } finally {
      setLoading(false);
    }
  };

  const runFullScan = async () => {
    setScanLoading(true);
    try {
      console.log('Starting full scan...');
      const response = await fetch('http://localhost:5000/api/full-scan');
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      console.log('Full scan completed:', data);
      alert(`Full scan completed! Found ${data.results?.summary?.suspicious_processes || 0} suspicious processes and ${data.results?.summary?.suspicious_connections || 0} suspicious connections.`);
    } catch (error) {
      console.error('Error running full scan:', error);
      alert('Failed to run full scan. Please ensure the backend is running.');
    } finally {
      setScanLoading(false);
    }
  };

  const saveCurrentState = async () => {
    try {
      console.log('Saving current state...');
      const response = await fetch('http://localhost:5000/api/save-scan');
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      console.log('State saved:', data);
      alert(`State saved successfully to ${data.filename}`);
    } catch (error) {
      console.error('Error saving state:', error);
      alert('Failed to save state. Please ensure the backend is running.');
    }
  };

  const viewLogs = () => {
    console.log('Opening logs...');
    // Try to download the last scan file
    window.open('http://localhost:5000/last_scan.json', '_blank');
  };

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, []);

  const getCpuStatus = (percent: number) => {
    if (percent > 80) return 'danger';
    if (percent > 60) return 'warning';
    return 'normal';
  };

  const getMemoryStatus = (percent: number) => {
    if (percent > 85) return 'danger';
    if (percent > 70) return 'warning';
    return 'normal';
  };

  if (loading) {
    return (
      <div className="space-y-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">System Overview</h2>
          <p className="text-gray-400">Real-time system monitoring and analysis</p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="bg-slate-800 rounded-lg p-6 animate-pulse">
              <div className="h-4 bg-slate-700 rounded w-3/4 mb-2"></div>
              <div className="h-8 bg-slate-700 rounded w-1/2"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (backendStatus === 'disconnected') {
    return (
      <div className="space-y-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">System Overview</h2>
          <p className="text-gray-400">Real-time system monitoring and analysis</p>
        </div>
        
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-6 text-center">
          <h3 className="text-red-400 font-semibold text-lg mb-2">Backend Connection Failed</h3>
          <p className="text-red-300 mb-4">
            Cannot connect to Flask backend at http://localhost:5000
          </p>
          <p className="text-gray-400 text-sm mb-4">
            Make sure your Flask backend is running:
            <br />
            <code className="bg-slate-800 px-2 py-1 rounded">cd backend && python app.py</code>
          </p>
          <button 
            onClick={fetchMetrics}
            className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">System Overview</h2>
          <p className="text-gray-400">Real-time system monitoring and analysis</p>
        </div>
        <div className="flex items-center gap-4">
          <div className={`px-3 py-1 rounded-full text-xs font-medium ${
            backendStatus === 'connected' 
              ? 'bg-green-500/20 text-green-400' 
              : 'bg-red-500/20 text-red-400'
          }`}>
            Backend: {backendStatus === 'connected' ? 'Connected' : 'Disconnected'}
          </div>
          <div className="text-sm text-gray-400 bg-slate-800 px-4 py-2 rounded-lg">
            Last updated: {metrics?.timestamp ? new Date(metrics.timestamp).toLocaleTimeString() : 'N/A'}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatusCard
          title="CPU Usage"
          value={`${metrics?.cpu_percent?.toFixed(1) || 0}%`}
          status={getCpuStatus(metrics?.cpu_percent || 0)}
          icon={<Cpu size={24} />}
        />
        
        <StatusCard
          title="Memory Usage"
          value={`${metrics?.memory_percent?.toFixed(1) || 0}%`}
          status={getMemoryStatus(metrics?.memory_percent || 0)}
          icon={<MemoryStick size={24} />}
        />
        
        <StatusCard
          title="System Status"
          value={backendStatus === 'connected' ? 'Online' : 'Offline'}
          status={backendStatus === 'connected' ? 'normal' : 'danger'}
          icon={<Activity size={24} />}
        />
        
        <StatusCard
          title="Network"
          value="Active"
          status="normal"
          icon={<Network size={24} />}
        />
      </div>

      <div className="bg-slate-800 rounded-lg p-8">
        <h3 className="text-xl font-semibold text-white mb-6">Quick Actions</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <button 
            onClick={runFullScan}
            disabled={scanLoading || backendStatus !== 'connected'}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white px-6 py-4 rounded-lg transition-colors font-medium"
          >
            {scanLoading ? 'Running Scan...' : 'Run Full Scan'}
          </button>
          <button 
            onClick={saveCurrentState}
            disabled={backendStatus !== 'connected'}
            className="bg-green-600 hover:bg-green-700 disabled:bg-green-400 text-white px-6 py-4 rounded-lg transition-colors font-medium"
          >
            Save Current State
          </button>
          <button 
            onClick={viewLogs}
            disabled={backendStatus !== 'connected'}
            className="bg-yellow-600 hover:bg-yellow-700 disabled:bg-yellow-400 text-white px-6 py-4 rounded-lg transition-colors font-medium"
          >
            View Logs
          </button>
        </div>
      </div>
    </div>
  );
};

export default Home;
