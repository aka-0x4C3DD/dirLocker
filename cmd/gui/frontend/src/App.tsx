import { useState, useEffect } from 'react';
import TitleBar from './components/TitleBar';

// Import Views
import WelcomeView from './views/WelcomeView';
import UnlockView from './views/UnlockView';
import CreateView from './views/CreateView';
import DashboardView from './views/DashboardView';

function App() {
    const [view, setView] = useState<'welcome' | 'unlock' | 'create' | 'dashboard'>('welcome');
    const [path, setPath] = useState('');
    const [password, setPassword] = useState('');
    const [status, setStatus] = useState('');
    const [isError, setIsError] = useState(false);
    const [toastMessage, setToastMessage] = useState('');

    useEffect(() => {
        if (toastMessage) {
            const timer = setTimeout(() => setToastMessage(''), 3000);
            return () => clearTimeout(timer);
        }
    }, [toastMessage]);

    const StatusMessage = () => {
        if (!status) return null;
        return (
            <div className={`mt-4 p-3 rounded text-sm ${isError ? 'bg-red-900/50 text-red-200 border border-red-800' : 'bg-green-900/50 text-green-200 border border-green-800'}`}>
                {status}
            </div>
        );
    };

    const Toast = () => {
        if (!toastMessage) return null;
        return (
            <div className="absolute top-16 left-1/2 transform -translate-x-1/2 bg-gray-800/90 text-white px-4 py-2 rounded-full border border-white/10 shadow-xl backdrop-blur-md text-sm z-50 animate-in fade-in slide-in-from-top-4 duration-300">
                <span className="flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                    {toastMessage}
                </span>
            </div>
        );
    };

    return (
        <div id="app" className="h-screen w-screen flex flex-col bg-background text-white selection:bg-brand-neon selection:text-black border border-white/5 overflow-hidden rounded-lg">
            <TitleBar />
            <Toast />

            <div className="flex-1 flex items-center justify-center p-8 relative overflow-hidden">
                {/* Background Decor */}
                <div className="absolute top-0 left-0 w-full h-full pointer-events-none opacity-20">
                    <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary rounded-full blur-[128px] mix-blend-screen"></div>
                    <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-accent rounded-full blur-[96px] mix-blend-screen"></div>
                </div>

                <div className="w-full max-w-md z-10">

                    {view === 'welcome' && (
                        <WelcomeView setView={setView} />
                    )}

                    {view === 'unlock' && (
                        <>
                            <UnlockView
                                path={path} setPath={setPath}
                                password={password} setPassword={setPassword}
                                setView={setView} setStatus={setStatus} setIsError={setIsError}
                            />
                            <StatusMessage />
                        </>
                    )}

                    {view === 'create' && (
                        <>
                            <CreateView
                                path={path} setPath={setPath}
                                password={password} setPassword={setPassword}
                                setView={setView} setStatus={setStatus} setIsError={setIsError}
                                setToastMessage={setToastMessage}
                            />
                            <StatusMessage />
                        </>
                    )}

                    {view === 'dashboard' && (
                        <DashboardView setView={setView} />
                    )}
                </div>

                <div className="absolute bottom-4 text-xs text-gray-600 font-mono">
                    v0.2.1 • BUILT WITH WAILS + REACT + RUST CORE
                </div>
            </div>
        </div>
    )
}

export default App
