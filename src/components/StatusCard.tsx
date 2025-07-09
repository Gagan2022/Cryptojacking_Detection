
import React from 'react';

interface StatusCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  status?: 'normal' | 'warning' | 'danger';
  icon?: React.ReactNode;
}

const StatusCard = ({ title, value, subtitle, status = 'normal', icon }: StatusCardProps) => {
  const getStatusColors = () => {
    switch (status) {
      case 'danger':
        return 'border-red-500 bg-red-500/10';
      case 'warning':
        return 'border-yellow-500 bg-yellow-500/10';
      default:
        return 'border-green-500 bg-green-500/10';
    }
  };

  return (
    <div className={`bg-slate-800 rounded-lg p-6 border-l-4 ${getStatusColors()} h-full`}>
      <div className="flex items-center justify-between h-full">
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wide mb-2">{title}</h3>
          <p className="text-2xl font-bold text-white mb-1 truncate">{value}</p>
          {subtitle && <p className="text-sm text-gray-400 truncate">{subtitle}</p>}
        </div>
        {icon && <div className="text-gray-400 ml-4 flex-shrink-0">{icon}</div>}
      </div>
    </div>
  );
};

export default StatusCard;
