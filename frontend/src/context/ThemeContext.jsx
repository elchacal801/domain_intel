import { createContext, useContext, useEffect } from 'react';

const ThemeContext = createContext();

export function ThemeProvider({ children }) {
    useEffect(() => {
        document.documentElement.setAttribute('data-theme', 'dark');
    }, []);

    return (
        <ThemeContext.Provider value={{ theme: 'dark' }}>
            {children}
        </ThemeContext.Provider>
    );
}

export function useTheme() {
    return useContext(ThemeContext);
}
