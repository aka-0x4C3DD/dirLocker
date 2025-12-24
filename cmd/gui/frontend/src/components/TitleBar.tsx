import { WindowMinimise, WindowToggleMaximise, Quit } from "../../wailsjs/runtime/runtime";
import { useState } from "react";

const TitleBar = () => {
    const [isMaximized, setIsMaximized] = useState(false);

    const handleMaximize = () => {
        WindowToggleMaximise();
        setIsMaximized(!isMaximized);
    };

    return (
        <div id="titlebar" className="h-8 w-full flex select-none bg-background/80 backdrop-blur-md border-b border-white/5" style={{ "--wails-draggable": "drag" } as React.CSSProperties}>
            <div className="flex-1 flex items-center px-4 font-mono text-xs text-primary/70 tracking-widest uppercase">
                dirLocker // v1.0.0
            </div>
            <div className="flex no-drag">
                <button
                    onClick={WindowMinimise}
                    className="h-8 w-12 flex items-center justify-center hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
                >
                    <svg width="10" height="1" viewBox="0 0 10 1" fill="currentColor">
                        <path d="M0 0h10v1H0z" />
                    </svg>
                </button>
                <button
                    onClick={handleMaximize}
                    className="h-8 w-12 flex items-center justify-center hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
                >
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor">
                        <rect x="1.5" y="1.5" width="7" height="7" />
                    </svg>
                </button>
                <button
                    onClick={Quit}
                    className="h-8 w-12 flex items-center justify-center hover:bg-red-500/80 text-gray-400 hover:text-white transition-colors"
                >
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor">
                        <path d="M1 1l8 8M9 1L1 9" />
                    </svg>
                </button>
            </div>
        </div>
    );
};

export default TitleBar;
