import React from 'react';

interface WelcomeViewProps {
    setView: (view: 'welcome' | 'unlock' | 'create' | 'dashboard') => void;
}

const WelcomeView: React.FC<WelcomeViewProps> = ({ setView }) => {
    return (
        <div className="space-y-8 animate-in fade-in zoom-in duration-500">
            <div className="text-center space-y-2">
                <h1 className="text-5xl font-bold tracking-tighter bg-clip-text text-transparent bg-gradient-to-br from-white to-gray-500">
                    dirLocker
                </h1>
                <p className="text-gray-400 font-mono text-sm">SECURE. PLAUSIBLE. DENIABLE.</p>
            </div>

            <div className="grid grid-cols-1 gap-4">
                <button
                    onClick={() => setView('unlock')}
                    className="group relative px-6 py-4 bg-surface hover:bg-surface/80 border border-white/10 rounded-xl transition-all hover:scale-[1.02] hover:shadow-lg hover:shadow-primary/20 text-left"
                >
                    <div className="text-lg font-bold group-hover:text-primary transition-colors">Access Existing Vault</div>
                    <div className="text-sm text-gray-500">Decrypt and mount a secure container</div>
                </button>

                <button
                    onClick={() => setView('create')}
                    className="group relative px-6 py-4 bg-surface hover:bg-surface/80 border border-white/10 rounded-xl transition-all hover:scale-[1.02] hover:shadow-lg hover:shadow-accent/20 text-left"
                >
                    <div className="text-lg font-bold group-hover:text-accent transition-colors">Initialize New Vault</div>
                    <div className="text-sm text-gray-500">Create a new encrypted container</div>
                </button>
            </div>
        </div>
    );
};

export default WelcomeView;
