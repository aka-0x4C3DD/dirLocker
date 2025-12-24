import React, { useState } from 'react';
import { OpenVault, BiometricsGet, GetVaultID } from '../../wailsjs/go/main/App';

interface UnlockViewProps {
    path: string;
    setPath: (path: string) => void;
    password: string;
    setPassword: (password: string) => void;
    setView: (view: 'welcome' | 'unlock' | 'create' | 'dashboard') => void;
    setStatus: (status: string) => void;
    setIsError: (isError: boolean) => void;
}

const UnlockView: React.FC<UnlockViewProps> = ({ path, setPath, password, setPassword, setView, setStatus, setIsError }) => {

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

    const handleBiometricUnlock = async () => {
        if (!path) {
            setStatus("Please provide the vault path first.");
            setIsError(true);
            return;
        }
        try {
            setStatus("Authenticating with Windows Hello...");

            // Try to get Vault UUID for binding
            let lookupKey = path;
            try {
                const vaultUuid = await GetVaultID(path);
                if (vaultUuid) {
                    lookupKey = vaultUuid;
                    console.log("Using Vault UUID for biometric lookup:", vaultUuid);
                }
            } catch (ignore) {
                console.warn("Could not retrieve Vault UUID, falling back to path binding.", ignore);
            }

            const storedPass = await BiometricsGet("dirLocker", lookupKey);
            if (storedPass) {
                setPassword(storedPass); // Fill it in for visibility
                await OpenVault(path, storedPass);
                setStatus("Unlocked via Biometrics.");
                setIsError(false);
                setView('dashboard');
            } else {
                // Backward compatibility: If looking up by UUID failed, try looking up by path (old method)
                if (lookupKey !== path) {
                    console.log("UUID lookup failed, trying legacy path lookup...");
                    const legacyPass = await BiometricsGet("dirLocker", path);
                    if (legacyPass) {
                        setPassword(legacyPass);
                        await OpenVault(path, legacyPass);
                        setStatus("Unlocked via Biometrics (Legacy Binding).");
                        setIsError(false);
                        setView('dashboard');
                        return;
                    }
                }

                setStatus("No credential found for this vault.");
                setIsError(true);
            }
        } catch (err) {
            setStatus("Biometric unlock failed: " + String(err));
            setIsError(true);
        }
    }

    return (
        <div className="bg-surface/50 backdrop-blur-xl border border-white/10 p-8 rounded-2xl shadow-2xl animate-in slide-in-from-bottom-4 duration-300">
            <div className="mb-6 flex items-center justify-between">
                <h2 className="text-2xl font-bold">Unlock Vault</h2>
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
                    <div className="relative">
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="••••••••••••••"
                            className="w-full bg-black/40 border border-white/10 rounded-lg px-4 py-3 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all text-sm font-mono pr-10"
                        />
                    </div>
                </div>

                <div className="space-y-3">
                    <button
                        onClick={handleUnlock}
                        className="w-full py-3 bg-primary hover:bg-blue-600 text-white font-bold rounded-lg transition-all shadow-lg shadow-blue-500/20 mt-4"
                    >
                        Unlock System
                    </button>
                    <button
                        onClick={handleBiometricUnlock}
                        className="w-full py-3 bg-transparent border border-white/10 hover:bg-white/5 text-gray-300 font-bold rounded-lg transition-all flex items-center justify-center gap-2"
                        title="Use Windows Hello or Touch ID"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.2-2.858.5-4m1.5 8l1-1" />
                        </svg>
                        Unlock using Biometrics
                    </button>
                </div>
            </div>
        </div>
    );
};

export default UnlockView;
