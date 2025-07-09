import React, { useState, useEffect } from 'react';
import DataTable from '../DataTable';
import { AlertTriangle, Shield, WifiOff } from 'lucide-react';

const NetworkMonitor = () => {
  const [connections, setConnections] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchConnections = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/network-connections');
      
      if (!response.ok) {
        const errorData = await response.json();
        setError(errorData.error || 'Network monitoring unavailable');
        return;
      }
      
      const data = await response.json();
      setConnections(data);
      setError(null);
    } catch (error) {
      console.error('Error fetching network connections:', error);
      setError('Failed to fetch network data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConnections();
    const interval = setInterval(fetchConnections, 8000); // 8 second refresh
    return () => clearInterval(interval);
  }, []);

  const suspiciousCount = connections.filter(c => c.suspicious).length;
  const totalCount = connections.length;

  const columns = [
    { key: 'pid', label: 'PID' },
    { key: 'laddr', label: 'Local Address' },
    { key: 'raddr', label: 'Remote Address' },
    { key: 'status', label: 'Status' },
    { 
      key: 'suspicious', 
      label: 'Security Status',
      render: (value: boolean) => (
        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
          value 
            ? 'bg-red-500/20 text-red-400' 
            : 'bg-green-500/20 text-green-400'
        }`}>
          {value ? (
            <>
              <AlertTriangle size={12} className="mr-1" />
              Suspicious Port
            </>
          ) : (
            <>
              <Shield size={12} className="mr-1" />
              Safe
            </>
          )}
        </span>
      )
    }
  ];

  if (error) {
    return (
      <div className="space-y-6">
        <h2 className="text-2xl font-bold text-white">Network Monitor</h2>
        
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-6 text-center">
          <WifiOff className="mx-auto text-red-400 mb-4" size={48} />
          <h3 className="text-red-400 font-semibold text-lg mb-2">Network Monitoring Unavailable</h3>
          <p className="text-red-300">{error}</p>
          <button 
            onClick={fetchConnections}
            className="mt-4 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Network Monitor</h2>
        <div className="text-sm text-gray-400">
          Auto-refresh: 8s | {totalCount} active connections
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-800 rounded-lg p-6 border-l-4 border-blue-500">
          <h3 className="text-sm font-medium text-gray-400 uppercase">Active Connections</h3>
          <p className="text-2xl font-bold text-white mt-2">{totalCount}</p>
        </div>
        
        <div className={`bg-slate-800 rounded-lg p-6 border-l-4 ${
          suspiciousCount > 0 ? 'border-red-500' : 'border-green-500'
        }`}>
          <h3 className="text-sm font-medium text-gray-400 uppercase">Suspicious Ports</h3>
          <p className={`text-2xl font-bold mt-2 ${
            suspiciousCount > 0 ? 'text-red-400' : 'text-green-400'
          }`}>
            {suspiciousCount}
          </p>
        </div>
        
        <div className="bg-slate-800 rounded-lg p-6 border-l-4 border-green-500">
          <h3 className="text-sm font-medium text-gray-400 uppercase">Safe Connections</h3>
          <p className="text-2xl font-bold text-green-400 mt-2">{totalCount - suspiciousCount}</p>
        </div>
      </div>

      {/* Network Connections Table */}
      <DataTable
        title="Network Connections"
        columns={columns}
        data={connections}
        loading={loading}
      />

      {/* Security Alert */}
      {suspiciousCount > 0 && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="text-red-400 mr-2" size={20} />
            <h3 className="text-red-400 font-semibold">Network Security Alert</h3>
          </div>
          <p className="text-red-300 mt-2">
            {suspiciousCount} connection{suspiciousCount > 1 ? 's' : ''} detected on suspicious ports. 
            These may indicate potential security threats or unauthorized access attempts.
          </p>
        </div>
      )}
    </div>
  );
};

export default NetworkMonitor;
