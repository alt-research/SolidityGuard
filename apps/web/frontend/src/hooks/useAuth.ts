import { useState, useEffect, useCallback } from 'react';

const TOKEN_KEY = 'solidityguard_token';
const isTauri = !!(window as unknown as Record<string, unknown>).__TAURI__;

export interface User {
  id: string;
  email: string;
  name: string;
  picture: string;
}

function parseJwt(token: string): Record<string, unknown> | null {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
  } catch {
    return null;
  }
}

const DESKTOP_USER: User = {
  id: 'desktop',
  email: 'local@solidityguard.desktop',
  name: 'Desktop User',
  picture: '',
};

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const loadUser = useCallback(() => {
    // Desktop app: skip auth, use local user
    if (isTauri) {
      setUser(DESKTOP_USER);
      setLoading(false);
      return;
    }

    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }

    const payload = parseJwt(token);
    if (!payload || (payload.exp as number) * 1000 < Date.now()) {
      localStorage.removeItem(TOKEN_KEY);
      setUser(null);
      setLoading(false);
      return;
    }

    setUser({
      id: payload.sub as string,
      email: payload.email as string,
      name: payload.name as string || '',
      picture: payload.picture as string || '',
    });
    setLoading(false);
  }, []);

  useEffect(() => {
    // Check for token in URL (OAuth callback redirect)
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
      // Remove token from URL
      window.history.replaceState({}, '', window.location.pathname);
    }

    loadUser();
  }, [loadUser]);

  const login = () => {
    if (isTauri) return; // No OAuth in desktop mode
    const baseUrl = import.meta.env.VITE_API_URL || '';
    window.location.href = `${baseUrl}/auth/google/login`;
  };

  const logout = () => {
    if (isTauri) return; // Can't logout from desktop mode
    localStorage.removeItem(TOKEN_KEY);
    setUser(null);
  };

  const getToken = (): string | null => {
    if (isTauri) return 'desktop-token';
    return localStorage.getItem(TOKEN_KEY);
  };

  return { user, loading, login, logout, getToken };
}
