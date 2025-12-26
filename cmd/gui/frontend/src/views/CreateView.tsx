import React, { useState } from 'react';
import { CreateVault, BiometricsStore, GetVaultID } from '../../wailsjs/go/main/App';

interface CreateViewProps {
    path: string;
    setPath: (path: string) => void;
    password: string;
    setPassword: (password: string) => void;
    setView: (view: 'welcome' | 'unlock' | 'create' | 'dashboard') => void;
    setStatus: (status: string) => void;
    setIsError: (isError: boolean) => void;
    setToastMessage: (msg: string) => void;
}

const CreateView: React.FC<CreateViewProps> = ({ path, setPath, password, setPassword, setView, setStatus, setIsError, setToastMessage }) => {
    const [enableBiometrics, setEnableBiometrics] = useState(false);

    // Password Generator Configuration
    const [showGenSettings, setShowGenSettings] = useState(false);
    const [passLength, setPassLength] = useState(20);
    const [useUpper, setUseUpper] = useState(true);
    const [useLower, setUseLower] = useState(true);
    const [useNumbers, setUseNumbers] = useState(true);
    const [useSymbols, setUseSymbols] = useState(true);

    const generateStrongPassword = () => {
        let charset = "";
        if (useLower) charset += "abcdefghijklmnopqrstuvwxyz";
        if (useUpper) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (useNumbers) charset += "0123456789";
        if (useSymbols) charset += "!@#$%^&*()_+~`|}{[]:;?><,./-=";

        // Fallback if nothing selected
        if (charset === "") charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        let retVal = "";
        if (window.crypto?.getRandomValues) {
            const values = new Uint32Array(passLength);
            window.crypto.getRandomValues(values);
            for (let i = 0; i < passLength; i++) {
                retVal += charset[values[i] % charset.length];
            }
        } else {
            for (let i = 0; i < passLength; ++i) {
                retVal += charset.charAt(Math.floor(Math.random() * charset.length));
            }
        }
        return retVal;
    };

    const handleGeneratePassword = async () => {
        const newPass = generateStrongPassword();
        setPassword(newPass);
        try {
            if (navigator.clipboard) {
                await navigator.clipboard.writeText(newPass);
            }
            setToastMessage("Strong password generated & copied! (Clears in 30s)");

            // Auto-clear clipboard after 30 seconds
            setTimeout(async () => {
                try {
                    const currentText = await navigator.clipboard.readText();
                    if (currentText === newPass) {
                        await navigator.clipboard.writeText("");
                        console.log("Clipboard cleared by dirLocker security policy.");
                    }
                } catch (e) {
                    try { await navigator.clipboard.writeText(""); } catch (ignore) { }
                }
            }, 30000);

        } catch (err) {
            setToastMessage("Password generated (Copy failed)");
        }
    };

    const handleCreate = async () => {
        if (!path || !password) {
            setStatus("Please provide both path and password.");
            setIsError(true);
            return;
        }
        try {
            await CreateVault(path, password);

            if (enableBiometrics) {
                try {
                    // Get Vault UUID for binding
                    let storeKey = path;
                    try {
                        const vaultUuid = await GetVaultID(path);
                        if (vaultUuid) {
                            storeKey = vaultUuid;
                        }
                    } catch (e) {
                        console.warn("Failed to get UUID for biometrics, falling back to path", e);
                    }

                    await BiometricsStore("dirLocker", storeKey, password);
                    setToastMessage("Vault created & Biometrics enabled!");
                } catch (bioErr) {
                    console.error("Biometrics error:", bioErr);
                    setToastMessage("Vault created, but Biometrics setup failed.");
                }
            } else {
                setStatus("Vault created successfully! You can now unlock it.");
            }

            setIsError(false);
            setView('unlock');
        } catch (err) {
            setStatus(String(err));
            setIsError(true);
        }
    };

    return (
        <div className="bg-surface/50 backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-2xl animate-in slide-in-from-bottom-4 duration-300 relative">
            <div className="mb-6 flex items-center justify-between">
                <h2 className="text-2xl font-bold">Initialize Vault</h2>
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
                    <label className="text-xs font-mono text-gray-400 uppercase flex justify-between items-center">
                        <span>Master Password</span>
                        <button
                            onClick={() => { setShowGenSettings(!showGenSettings); }}
                            className={`text-[10px] uppercase tracking-wider hover:text-accent transition-colors ${showGenSettings ? 'text-accent' : 'text-gray-600'}`}
                        >
                            {showGenSettings ? 'Hide Options' : 'Options'}
                        </button>
                    </label>
                    <div className="relative">
                        <input
                            type="text"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="••••••••••••••"
                            className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-3 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all text-sm font-mono pr-10"
                        />
                        <button
                            onClick={handleGeneratePassword}
                            className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-gray-400 hover:text-accent transition-colors rounded-md hover:bg-white/5"
                            title="Generate Strong Password"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 12c0-1.232-.046-2.453-.138-3.662a4.006 4.006 0 00-3.7-3.7 48.678 48.678 0 00-7.324 0 4.006 4.006 0 00-3.7 3.7c-.017.22-.032.441-.046.662M19.5 12l3-3m-3 3l-3-3m-12 3c0 1.232.046 2.453.138 3.662a4.006 4.006 0 003.7 3.7 48.656 48.656 0 007.324 0 4.006 4.006 0 003.7-3.7c.017-.22.032-.441.046-.662M4.5 12l3 3m-3-3l-3 3" />
                            </svg>
                        </button>
                    </div>

                    {/* Optional Generator Settings Panel */}
                    {showGenSettings && (
                        <div className="mt-2 p-3 bg-black/30 border border-white/5 rounded-lg text-xs space-y-3 animate-in slide-in-from-top-2">
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">Length: <span className="text-white font-mono">{passLength}</span></span>
                                <input
                                    type="range" min="8" max="64"
                                    value={passLength}
                                    onChange={(e) => { setPassLength(Number(e.target.value)); }}
                                    className="w-32 h-1 bg-gray-700 rounded-lg appearance-none cursor-pointer"
                                />
                            </div>
                            <div className="grid grid-cols-2 gap-2 text-gray-400">
                                <label className="flex items-center gap-2 cursor-pointer hover:text-white">
                                    <input type="checkbox" checked={useUpper} onChange={() => { setUseUpper(!useUpper); }} className="rounded border-gray-700 bg-gray-900 text-accent/80 focus:ring-0" />
                                    A-Z
                                </label>
                                <label className="flex items-center gap-2 cursor-pointer hover:text-white">
                                    <input type="checkbox" checked={useLower} onChange={() => { setUseLower(!useLower); }} className="rounded border-gray-700 bg-gray-900 text-accent/80 focus:ring-0" />
                                    a-z
                                </label>
                                <label className="flex items-center gap-2 cursor-pointer hover:text-white">
                                    <input type="checkbox" checked={useNumbers} onChange={() => { setUseNumbers(!useNumbers); }} className="rounded border-gray-700 bg-gray-900 text-accent/80 focus:ring-0" />
                                    0-9
                                </label>
                                <label className="flex items-center gap-2 cursor-pointer hover:text-white">
                                    <input type="checkbox" checked={useSymbols} onChange={() => { setUseSymbols(!useSymbols); }} className="rounded border-gray-700 bg-gray-900 text-accent/80 focus:ring-0" />
                                    #$@
                                </label>
                            </div>
                        </div>
                    )}
                </div>

                <div className="flex items-center gap-2">
                    <input
                        type="checkbox"
                        id="biometrics"
                        checked={enableBiometrics}
                        onChange={(e) => { setEnableBiometrics(e.target.checked); }}
                        className="form-checkbox h-4 w-4 text-accent bg-black border-white/10 rounded focus:ring-offset-0 focus:ring-accent"
                    />
                    <label htmlFor="biometrics" className="text-sm text-gray-400 cursor-pointer hover:text-white transition-colors">
                        Enable Windows Hello / Biometrics
                    </label>
                </div>

                <button
                    onClick={handleCreate}
                    className="w-full py-3 bg-accent hover:bg-yellow-600 text-black font-bold rounded-lg transition-all shadow-lg shadow-yellow-500/20 mt-4"
                >
                    Create Container
                </button>
            </div>
        </div>
    );
};

export default CreateView;
