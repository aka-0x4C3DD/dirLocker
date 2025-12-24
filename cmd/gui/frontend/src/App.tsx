import { useState } from 'react';
import { CreateVault, OpenVault } from '../wailsjs/go/main/App';

function App() {
    const [view, setView] = useState<'welcome' | 'unlock' | 'create' | 'dashboard'>('welcome');
    const [path, setPath] = useState('');
    const [password, setPassword] = useState('');
    const [status, setStatus] = useState('');
    const [isError, setIsError] = useState(false);

    const handleCreate = async () => {
        if (!path || !password) {
            setStatus("Please provide both path and password.");
            setIsError(true);
            return;
        }
        try {
            await CreateVault(path, password);
            setStatus("Vault created successfully! You can now unlock it.");
            setIsError(false);
            setView('unlock');
        } catch (err) {
            setStatus(String(err));
            setIsError(true);
        }
    };

    const handleUnlock = async () => {
        if (!path || !password) {
            setStatus("Please provide both path and password.");
            setIsError(true);
            return;
        }
        try {
            await OpenVault(path, password);
            setStatus("Vault unlocked.");
            setIsError(false);
            setView('dashboard');
        } catch (err) {
            setStatus(String(err));
            setIsError(true);
        }
    };

    const StatusMessage = () => {
        if (!status) return null;
        return (
            <div className={`mt-4 p-3 rounded text-sm ${isError ? 'bg-red-900/50 text-red-200 border border-red-800' : 'bg-green-900/50 text-green-200 border border-green-800'}`}>
                {status}
            </div>
        );
    };

    return (
        <div id="app" className="h-screen w-screen flex flex-col bg-background text-white selection:bg-brand-neon selection:text-black">
            {/* Header/Title Bar Area (Draggable) */}
            <div className="w-full h-8 bg-surface/50 border-b border-white/5 flex items-center justify-center select-none" style={{ widows: 1 }}>
                <span className="text-xs font-mono text-gray-500 tracking-widest">DIRLOCKER // SECURE VAULT SYSTEM</span>
            </div>

            <div className="flex-1 flex items-center justify-center p-8 relative overflow-hidden">
                {/* Background Decor */}
                <div className="absolute top-0 left-0 w-full h-full pointer-events-none opacity-20">
                    <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary rounded-full blur-[128px] mix-blend-screen"></div>
                    <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-accent rounded-full blur-[96px] mix-blend-screen"></div>
                </div>

                <div className="w-full max-w-md z-10">

                    {view === 'welcome' && (
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
                    )}

                    {(view === 'unlock' || view === 'create') && (
                        <div className="bg-surface/50 backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-2xl animate-in slide-in-from-bottom-4 duration-300">
                            <div className="mb-6 flex items-center justify-between">
                                <h2 className="text-2xl font-bold">{view === 'unlock' ? 'Unlock Vault' : 'Initialize Vault'}</h2>
                                <button onClick={() => { setView('welcome'); setStatus(''); }} className="text-sm text-gray-500 hover:text-white transition-colors">Back</button>
                            </div>

                            <div className="space-y-4">
                                <div className="space-y-2">
                                    <label className="text-xs font-mono text-gray-400 uppercase">Vault Path</label>
                                    <input
                                        type="text"
                                        value={path}
                                        onChange={(e) => setPath(e.target.value)}
                                        placeholder="C:\secure\my_vault.dat"
                                        className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-3 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all text-sm font-mono"
                                    />
                                </div>

                                <div className="space-y-2">
                                    <label className="text-xs font-mono text-gray-400 uppercase">Master Password</label>
                                    <input
                                        type="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        placeholder="••••••••••••••"
                                        className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-3 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all text-sm font-mono"
                                    />
                                </div>

                                {view === 'unlock' ? (
                                    <button
                                        onClick={handleUnlock}
                                        className="w-full py-3 bg-primary hover:bg-blue-600 text-white font-bold rounded-lg transition-all shadow-lg shadow-blue-500/20 mt-4"
                                    >
                                        Unlock System
                                    </button>
                                ) : (
                                    <button
                                        onClick={handleCreate}
                                        className="w-full py-3 bg-accent hover:bg-yellow-600 text-black font-bold rounded-lg transition-all shadow-lg shadow-yellow-500/20 mt-4"
                                    >
                                        Create Container
                                    </button>
                                )}
                            </div>
                            <StatusMessage />
                        </div>
                    )}

                    {view === 'dashboard' && (
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
                    )}
                </div>

                <div className="absolute bottom-4 text-xs text-gray-600 font-mono">
                    v0.2.0 • BUILT WITH WAILS + REACT + RUST CORE
                </div>
            </div>
        </div>
    )
}

export default App
