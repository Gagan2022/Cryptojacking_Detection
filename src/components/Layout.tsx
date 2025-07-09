
import React from 'react';
import { useState } from 'react';
import { Monitor, Cpu, Activity, Network, AlertTriangle, Menu, X } from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
  currentTab: string;
  onTabChange: (tab: string) => void;
}

const Layout = ({ children, currentTab, onTabChange }: LayoutProps) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const navItems = [
    { id: 'home', label: 'Home', icon: Monitor },
    { id: 'cpu-memory', label: 'CPU & Memory', icon: Cpu },
    { id: 'processes', label: 'Process Monitor', icon: Activity },
    { id: 'network', label: 'Network Monitor', icon: Network },
    { id: 'traffic', label: 'Traffic Anomalies', icon: AlertTriangle },
  ];

  return (
    <div className="min-h-screen bg-slate-900 text-white flex">
      {/* Mobile menu button */}
      <div className="lg:hidden fixed top-4 left-4 z-50">
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="bg-slate-800 p-2 rounded-lg text-white hover:bg-slate-700 transition-colors shadow-lg"
        >
          {sidebarOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </div>

      {/* Sidebar */}
      <div className={`fixed inset-y-0 left-0 z-40 w-64 bg-slate-800 border-r border-slate-700 transform transition-transform duration-300 ease-in-out ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      } lg:translate-x-0 lg:static lg:inset-0 flex-shrink-0`}>
        <div className="flex items-center justify-center h-16 bg-slate-900 border-b border-slate-700 px-4">
          <h1 className="text-xl font-bold text-blue-400">System Monitor</h1>
        </div>
        
        <nav className="mt-8 px-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => {
                  onTabChange(item.id);
                  setSidebarOpen(false);
                }}
                className={`w-full flex items-center px-4 py-3 mb-2 text-left hover:bg-slate-700 transition-colors rounded-lg ${
                  currentTab === item.id ? 'bg-slate-700 border-r-2 border-blue-400 text-blue-400' : 'text-gray-300'
                }`}
              >
                <Icon size={20} className="mr-3 flex-shrink-0" />
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Main content */}
      <div className="flex-1 min-w-0 lg:ml-0 ml-0">
        <div className="h-full p-6 pt-16 lg:pt-6">
          {children}
        </div>
      </div>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
};

export default Layout;
