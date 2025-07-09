import React, { useState, useEffect } from 'react';
import StatusCard from '../StatusCard';
import { Cpu, MemoryStick, Clock } from 'lucide-react';

const CpuMemory = () => {
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [history, setHistory] = useState<any[]>([]);

  const fetchMetrics = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/cpu-memory');
      const data = await response.json();
      setMetrics(data);
      
      // Add to history for simple trending
      setHistory(prev => {
        const newHistory = [...prev, data];
        return newHistory.slice(-10); // Keep last 10 readings
      });
    } catch (error) {
      console.error('Error fetching CPU/Memory metrics:', error);
    } finally {
      setLoading(false);
    }
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
      <div className="space-y-6">
        <h2 className="text-2xl font-bold text-white">CPU & Memory Monitoring</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[1, 2, 3].map((i) => (
            <div key={i} className="bg-slate-800 rounded-lg p-6 animate-pulse">
              <div className="h-4 bg-slate-700 rounded w-3/4 mb-2"></div>
              <div className="h-8 bg-slate-700 rounded w-1/2"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">CPU & Memory Monitoring</h2>
        <div className="text-sm text-gray-400">
          Auto-refresh: 5s | Last updated: {metrics?.timestamp ? new Date(metrics.timestamp).toLocaleTimeString() : 'N/A'}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <StatusCard
          title="CPU Usage"
          value={`${metrics?.cpu_percent?.toFixed(1) || 0}%`}
          subtitle="Current utilization"
          status={getCpuStatus(metrics?.cpu_percent || 0)}
          icon={<Cpu size={24} />}
        />
        
        <StatusCard
          title="Memory Usage"
          value={`${metrics?.memory_percent?.toFixed(1) || 0}%`}
          subtitle="RAM utilization"
          status={getMemoryStatus(metrics?.memory_percent || 0)}
          icon={<MemoryStick size={24} />}
        />
        
        <StatusCard
          title="Last Check"
          value={metrics?.timestamp ? new Date(metrics.timestamp).toLocaleTimeString() : 'N/A'}
          subtitle="System timestamp"
          status="normal"
          icon={<Clock size={24} />}
        />
      </div>

      {/* Historical Data */}
      <div className="bg-slate-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Recent History</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-700">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Time</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">CPU %</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Memory %</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {history.slice(-5).reverse().map((reading, index) => (
                <tr key={index} className="hover:bg-slate-700/50">
                  <td className="px-4 py-2 text-sm text-gray-300">
                    {new Date(reading.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-2 text-sm text-gray-300">
                    {reading.cpu_percent?.toFixed(1)}%
                  </td>
                  <td className="px-4 py-2 text-sm text-gray-300">
                    {reading.memory_percent?.toFixed(1)}%
                  </td>
                  <td className="px-4 py-2 text-sm">
                    <span className={`px-2 py-1 rounded-full text-xs ${
                      reading.cpu_percent > 80 || reading.memory_percent > 85
                        ? 'bg-red-500/20 text-red-400'
                        : reading.cpu_percent > 60 || reading.memory_percent > 70
                        ? 'bg-yellow-500/20 text-yellow-400'
                        : 'bg-green-500/20 text-green-400'
                    }`}>
                      {reading.cpu_percent > 80 || reading.memory_percent > 85
                        ? 'High Load'
                        : reading.cpu_percent > 60 || reading.memory_percent > 70
                        ? 'Moderate'
                        : 'Normal'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default CpuMemory;
