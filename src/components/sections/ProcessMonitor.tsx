import React, { useState, useEffect } from 'react';
import DataTable from '../DataTable';
import { AlertTriangle, Shield } from 'lucide-react';

const ProcessMonitor = () => {
  const [processes, setProcesses] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchProcesses = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/processes');
      const data = await response.json();
      setProcesses(data);
    } catch (error) {
      console.error('Error fetching processes:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProcesses();
    const interval = setInterval(fetchProcesses, 10000); // 10 second refresh for processes
    return () => clearInterval(interval);
  }, []);

  const suspiciousCount = processes.filter(p => p.suspicious).length;
  const totalCount = processes.length;

  const columns = [
    { key: 'pid', label: 'PID' },
    { key: 'name', label: 'Process Name' },
    { 
      key: 'cmdline', 
      label: 'Command Line',
      render: (value: string) => (
        <div className="max-w-xs truncate" title={value}>
          {value || 'N/A'}
        </div>
      )
    },
    { 
      key: 'cpu_percent', 
      label: 'CPU %',
      render: (value: number) => `${value?.toFixed(1) || 0}%`
    },
    { 
      key: 'memory_percent', 
      label: 'Memory %',
      render: (value: number) => `${value?.toFixed(1) || 0}%`
    },
    { 
      key: 'create_time', 
      label: 'Started',
      render: (value: string) => new Date(value).toLocaleTimeString()
    },
    { 
      key: 'suspicious', 
      label: 'Status',
      render: (value: boolean) => (
        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
          value 
            ? 'bg-red-500/20 text-red-400' 
            : 'bg-green-500/20 text-green-400'
        }`}>
          {value ? (
            <>
              <AlertTriangle size={12} className="mr-1" />
              Suspicious
            </>
          ) : (
            <>
              <Shield size={12} className="mr-1" />
              Clean
            </>
          )}
        </span>
      )
    }
  ];

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Process Monitor</h2>
          <p className="text-gray-400">Monitor running processes and detect suspicious activity</p>
        </div>
        <div className="text-sm text-gray-400 bg-slate-800 px-4 py-2 rounded-lg">
          Auto-refresh: 10s | {totalCount} processes running
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-slate-800 rounded-lg p-6 border-l-4 border-blue-500">
          <h3 className="text-sm font-medium text-gray-400 uppercase mb-2">Total Processes</h3>
          <p className="text-2xl font-bold text-white">{totalCount}</p>
        </div>
        
        <div className={`bg-slate-800 rounded-lg p-6 border-l-4 ${
          suspiciousCount > 0 ? 'border-red-500' : 'border-green-500'
        }`}>
          <h3 className="text-sm font-medium text-gray-400 uppercase mb-2">Suspicious</h3>
          <p className={`text-2xl font-bold ${
            suspiciousCount > 0 ? 'text-red-400' : 'text-green-400'
          }`}>
            {suspiciousCount}
          </p>
        </div>
        
        <div className="bg-slate-800 rounded-lg p-6 border-l-4 border-green-500">
          <h3 className="text-sm font-medium text-gray-400 uppercase mb-2">Clean</h3>
          <p className="text-2xl font-bold text-green-400">{totalCount - suspiciousCount}</p>
        </div>
      </div>

      {/* Process Table */}
      <div className="mb-8">
        <DataTable
          title="Running Processes"
          columns={columns}
          data={processes}
          loading={loading}
        />
      </div>

      {/* Suspicious Processes Alert */}
      {suspiciousCount > 0 && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-6">
          <div className="flex items-center mb-3">
            <AlertTriangle className="text-red-400 mr-2" size={20} />
            <h3 className="text-red-400 font-semibold text-lg">Security Alert</h3>
          </div>
          <p className="text-red-300">
            {suspiciousCount} suspicious process{suspiciousCount > 1 ? 'es' : ''} detected. 
            Review the processes marked as suspicious for potential security threats.
          </p>
        </div>
      )}
    </div>
  );
};

export default ProcessMonitor;
