import React from 'react';

interface DashboardViewProps {
    setView: (view: 'welcome' | 'unlock' | 'create' | 'dashboard') => void;
}

const DashboardView: React.FC<DashboardViewProps> = ({ setView }) => {
    return (
        <div className="bg-surface/50 backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-2xl text-center animate-in scale-95 duration-300">
            <div className="w-16 h-16 bg-green-500/20 text-green-400 rounded-full flex items-center justify-center mx-auto mb-4 border border-green-500/30">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
            </div>
            <h2 className="text-2xl font-bold mb-2">Access Granted</h2>
            <p className="text-gray-400 mb-6">Vault is mounted and active.</p>

            <div className="grid grid-cols-2 gap-3 mb-6">
                <div className="p-3 bg-black/30 rounded border border-white/5">
                    <div className="text-xs text-gray-500">STATUS</div>
                    <div className="text-green-400 font-mono">MOUNTED</div>
                </div>
                <div className="p-3 bg-black/30 rounded border border-white/5">
                    <div className="text-xs text-gray-500">ENCRYPTION</div>
                    <div className="text-blue-400 font-mono">XCHACHA20</div>
                </div>
            </div>

            <button
                onClick={() => setView('welcome')}
                className="w-full py-2 border border-white/10 hover:bg-white/5 rounded-lg transition-colors text-sm"
            >
                Lock & Exit
            </button>
        </div>
    );
};

export default DashboardView;
