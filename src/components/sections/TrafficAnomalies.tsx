import React, { useState, useEffect } from 'react';
import StatusCard from '../StatusCard';
import { TrendingUp, TrendingDown, AlertTriangle } from 'lucide-react';

const TrafficAnomalies = () => {
  const [trafficData, setTrafficData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [history, setHistory] = useState<any[]>([]);

  const fetchTrafficData = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/traffic-stats');
      const data = await response.json();
      setTrafficData(data);
      
      // Add timestamp and store in history
      const timestampedData = {
        ...data,
        timestamp: new Date().toISOString()
      };
      
      setHistory(prev => {
        const newHistory = [...prev, timestampedData];
        return newHistory.slice(-20); // Keep last 20 readings
      });
    } catch (error) {
      console.error('Error fetching traffic data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrafficData();
    const interval = setInterval(fetchTrafficData, 5000); // 5 second refresh
    return () => clearInterval(interval);
  }, []);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const getTrafficStatus = (anomaly: boolean) => {
    return anomaly ? 'danger' : 'normal';
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <h2 className="text-2xl font-bold text-white">Traffic Anomaly Detection</h2>
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
        <h2 className="text-2xl font-bold text-white">Traffic Anomaly Detection</h2>
        <div className="text-sm text-gray-400">
          Auto-refresh: 5s | Monitoring network traffic spikes
        </div>
      </div>

      {/* Current Traffic Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <StatusCard
          title="Sent Traffic"
          value={formatBytes(trafficData?.sent_bytes_per_sec || 0)}
          subtitle="Bytes per second"
          status={getTrafficStatus(trafficData?.anomaly)}
          icon={<TrendingUp size={24} />}
        />
        
        <StatusCard
          title="Received Traffic"
          value={formatBytes(trafficData?.recv_bytes_per_sec || 0)}
          subtitle="Bytes per second"
          status={getTrafficStatus(trafficData?.anomaly)}
          icon={<TrendingDown size={24} />}
        />
        
        <StatusCard
          title="Anomaly Status"
          value={trafficData?.anomaly ? "DETECTED" : "NORMAL"}
          subtitle="Traffic analysis"
          status={getTrafficStatus(trafficData?.anomaly)}
          icon={<AlertTriangle size={24} />}
        />
      </div>

      {/* Anomaly Alert */}
      {trafficData?.anomaly && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="text-red-400 mr-2" size={20} />
            <h3 className="text-red-400 font-semibold">Traffic Anomaly Detected</h3>
          </div>
          <p className="text-red-300 mt-2">
            Unusual network traffic spike detected. This could indicate data exfiltration, 
            DDoS activity, or other suspicious network behavior.
          </p>
        </div>
      )}

      {/* Traffic History */}
      <div className="bg-slate-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Traffic History</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-700">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Time</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Sent (B/s)</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Received (B/s)</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {history.slice(-10).reverse().map((reading, index) => (
                <tr key={index} className="hover:bg-slate-700/50">
                  <td className="px-4 py-2 text-sm text-gray-300">
                    {new Date(reading.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-2 text-sm text-gray-300">
                    {formatBytes(reading.sent_bytes_per_sec)}
                  </td>
                  <td className="px-4 py-2 text-sm text-gray-300">
                    {formatBytes(reading.recv_bytes_per_sec)}
                  </td>
                  <td className="px-4 py-2 text-sm">
                    <span className={`px-2 py-1 rounded-full text-xs ${
                      reading.anomaly
                        ? 'bg-red-500/20 text-red-400'
                        : 'bg-green-500/20 text-green-400'
                    }`}>
                      {reading.anomaly ? 'ANOMALY' : 'NORMAL'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Traffic Analysis Info */}
      <div className="bg-slate-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Analysis Parameters</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-gray-300">
          <div>
            <span className="text-gray-400">Anomaly Threshold:</span>
            <span className="ml-2 text-white">1 MB/s (1,000,000 bytes/sec)</span>
          </div>
          <div>
            <span className="text-gray-400">Measurement Interval:</span>
            <span className="ml-2 text-white">1 second sample</span>
          </div>
          <div>
            <span className="text-gray-400">Detection Method:</span>
            <span className="ml-2 text-white">Traffic spike detection</span>
          </div>
          <div>
            <span className="text-gray-400">Current Status:</span>
            <span className={`ml-2 ${trafficData?.anomaly ? 'text-red-400' : 'text-green-400'}`}>
              {trafficData?.anomaly ? 'Alert State' : 'Normal Operation'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TrafficAnomalies;
