
import React, { useState } from 'react';
import Layout from '../components/Layout';
import Home from '../components/sections/Home';
import CpuMemory from '../components/sections/CpuMemory';
import ProcessMonitor from '../components/sections/ProcessMonitor';
import NetworkMonitor from '../components/sections/NetworkMonitor';
import TrafficAnomalies from '../components/sections/TrafficAnomalies';

const Index = () => {
  const [currentTab, setCurrentTab] = useState('home');

  const renderContent = () => {
    switch (currentTab) {
      case 'home':
        return <Home />;
      case 'cpu-memory':
        return <CpuMemory />;
      case 'processes':
        return <ProcessMonitor />;
      case 'network':
        return <NetworkMonitor />;
      case 'traffic':
        return <TrafficAnomalies />;
      default:
        return <Home />;
    }
  };

  return (
    <Layout currentTab={currentTab} onTabChange={setCurrentTab}>
      {renderContent()}
    </Layout>
  );
};

export default Index;
