import React, { useState, useEffect, useCallback } from 'react';
import './App.css';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Badge } from './components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { QrCode, Factory, Scan, Users, BarChart3, Settings, LogOut, Camera, CheckCircle, Clock, Play, Pause, Plus, X, ChevronUp, ChevronDown, List, Database, Download, Loader2 } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Authentication Context
const AuthContext = React.createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token')); // Changed to localStorage for persistence
  const [loading, setLoading] = useState(true); // Add loading state for initial auth check

  // Function to verify token and get user data
  const verifyToken = useCallback(async (authToken) => {
    if (!authToken) {
      setLoading(false);
      return;
    }

    try {
      // Set the token in axios headers
      axios.defaults.headers.common['Authorization'] = `Bearer ${authToken}`;
      
      // Call the verify endpoint to get user data
      const response = await axios.get(`${API}/auth/verify`);
      setUser(response.data.user);
    } catch (error) {
      console.error('Token verification failed:', error);
      // If token is invalid, clear it
      localStorage.removeItem('token');
      setToken(null);
      delete axios.defaults.headers.common['Authorization'];
    } finally {
      setLoading(false);
    }
  }, []);

  // Check token on initial load
  useEffect(() => {
    verifyToken(token);
  }, [token, verifyToken]);

  // Set up axios interceptor to handle 401 errors (token expired)
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      response => response,
      error => {
        if (error.response && error.response.status === 401) {
          // Token expired or invalid, log the user out
          logout();
        }
        return Promise.reject(error);
      }
    );

    return () => {
      // Clean up interceptor on unmount
      axios.interceptors.response.eject(interceptor);
    };
  }, []);

  const login = async (username, password) => {
    try {
      const response = await axios.post(`${API}/auth/login`, { username, password });
      const { token, user } = response.data;
      
      localStorage.setItem('token', token); // Store token in localStorage for persistence
      setToken(token);
      setUser(user);
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      
      return { success: true };
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || 'Login failed' };
    }
  };

  const logout = () => {
    localStorage.removeItem('token'); // Remove from localStorage
    setToken(null);
    setUser(null);
    delete axios.defaults.headers.common['Authorization'];
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

// Protected Route Component
const ProtectedRoute = ({ element, requiredRoles = [] }) => {
  const { user, loading } = React.useContext(AuthContext);
  
  // Show loading state while checking authentication
  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-slate-800 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-white mx-auto mb-4" />
          <p className="text-white">Yükleniyor...</p>
        </div>
      </div>
    );
  }
  
  // If not authenticated, redirect to login
  if (!user) {
    return <Navigate to="/" replace />;
  }
  
  // If roles are specified and user doesn't have required role, show unauthorized
  if (requiredRoles.length > 0 && !requiredRoles.includes(user.role)) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-slate-800 flex items-center justify-center p-4">
        <Card className="w-full max-w-md bg-white/10 backdrop-blur-lg border-white/20">
          <CardHeader className="text-center">
            <CardTitle className="text-2xl text-white">Yetkisiz Erişim</CardTitle>
            <CardDescription className="text-gray-300">
              Bu sayfaya erişim yetkiniz bulunmamaktadır.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <Button 
              onClick={() => window.location.href = '/dashboard'} 
              className="bg-blue-600 hover:bg-blue-700"
            >
              Ana Sayfaya Dön
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }
  
  // If authenticated and authorized, render the element
  return element;
};

// Login Component
const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login, user } = React.useContext(AuthContext);
  const navigate = useNavigate();

  // If already logged in, redirect to dashboard
  useEffect(() => {
    if (user) {
      navigate('/dashboard');
    }
  }, [user, navigate]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    const result = await login(username, password);
    
    if (!result.success) {
      setError(result.error);
    } else {
      // Redirect based on role
      navigate('/dashboard');
    }
    
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-slate-800 flex items-center justify-center p-4">
      <Card className="w-full max-w-md bg-white/10 backdrop-blur-lg border-white/20">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 p-6 bg-white/10 rounded-full w-fit">
            <img 
              src="https://customer-assets.emergentagent.com/job_metalops/artifacts/i1dybgg7_Velar%20Makine%20Logo%20SVG.png" 
              alt="Velar Makine Logo" 
              className="h-[150px] w-[150px] object-contain"
            />
          </div>
          <CardTitle className="text-2xl text-white">Velar Makine <br /> Üretim Takip Sistemi</CardTitle>
          <CardDescription className="text-gray-300">
            Giriş yaparak üretim takip sistemine erişin
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <Input
                type="text"
                placeholder="Kullanıcı Adı"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="bg-white/10 border-white/20 text-white placeholder:text-gray-400"
                required
              />
            </div>
            <div>
              <Input
                type="password"
                placeholder="Şifre"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="bg-white/10 border-white/20 text-white placeholder:text-gray-400"
                required
              />
            </div>
            {error && (
              <div className="text-red-400 text-sm text-center">{error}</div>
            )}
            <Button 
              type="submit" 
              className="w-full bg-blue-600 hover:bg-blue-700"
              disabled={loading}
            >
              {loading ? 'Giriş yapılıyor...' : 'Giriş Yap'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

// Dedicated Operator QR Scanner Component (Full Screen)
const OperatorScanner = () => {
  const [qrCode, setQrCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [cameraActive, setCameraActive] = useState(false);
  const [cameraError, setCameraError] = useState('');
  const [manualMode, setManualMode] = useState(false);
  const [showConfirmDialog, setShowConfirmDialog] = useState(false);
  const [pendingQrCode, setPendingQrCode] = useState('');
  const { user, logout } = React.useContext(AuthContext);
  
  // New state for work order scanning
  const [workOrderData, setWorkOrderData] = useState(null);
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [actionType, setActionType] = useState('start');
  const [showProcessSelection, setShowProcessSelection] = useState(false);
  // New state for confirmation message
  const [showConfirmationMessage, setShowConfirmationMessage] = useState(false);
  
  const videoRef = React.useRef(null);
  const qrScannerRef = React.useRef(null);
  const isDialogShowing = React.useRef(false);

  // Initialize QR Scanner
  React.useEffect(() => {
    let QrScanner;
    
    const initScanner = async () => {
      try {
        // Dynamically import QrScanner
        const QrScannerModule = await import('qr-scanner');
        QrScanner = QrScannerModule.default;
        
        if (videoRef.current && !manualMode) {
          qrScannerRef.current = new QrScanner(
            videoRef.current,
            (result) => {
              // Only process if no dialog is currently showing
              if (result.data && !isDialogShowing.current) {
                isDialogShowing.current = true;
                setQrCode(result.data);
                setPendingQrCode(result.data);
                setShowConfirmDialog(true);
                // Pause scanning while showing confirmation dialog
                if (qrScannerRef.current) {
                  qrScannerRef.current.stop();
                  setCameraActive(false);
                }
              }
            },
            {
              highlightScanRegion: true,
              highlightCodeOutline: true,
              maxScansPerSecond: 5,
              preferredCamera: 'environment', // Use back camera on mobile
            }
          );
        }
      } catch (err) {
        console.error('Failed to initialize QR Scanner:', err);
        setCameraError('Failed to initialize camera scanner. Please use manual mode.');
        setManualMode(true);
      }
    };

    initScanner();

    return () => {
      if (qrScannerRef.current) {
        qrScannerRef.current.stop();
        qrScannerRef.current.destroy();
      }
    };
  }, [manualMode]);

  // Start camera
  const startCamera = async () => {
    if (!qrScannerRef.current || manualMode) return;
    
    try {
      setCameraError('');
      await qrScannerRef.current.start();
      setCameraActive(true);
    } catch (err) {
      console.error('Camera start failed:', err);
      let errorMessage = 'Camera access denied. ';
      
      if (err.name === 'NotAllowedError') {
        errorMessage += 'Please allow camera permissions and refresh the page.';
      } else if (err.name === 'NotFoundError') {
        errorMessage += 'No camera found on this device.';
      } else if (err.name === 'NotSupportedError') {
        errorMessage += 'Camera not supported in this browser.';
      } else {
        errorMessage += 'Please try manual mode instead.';
      }
      
      setCameraError(errorMessage);
      setManualMode(true);
    }
  };

  // Stop camera
  const stopCamera = () => {
    if (qrScannerRef.current) {
      qrScannerRef.current.stop();
      setCameraActive(false);
    }
  };

  // Handle scanning a work order QR code
  const handleWorkOrderScan = async (scannedCode) => {
    if (loading) return; // Prevent multiple simultaneous scans
    
    setLoading(true);
    setError('');
    setResult(null);
    setWorkOrderData(null);
    setShowProcessSelection(false);

    try {
      const response = await axios.post(`${API}/scan/work-order`, {
        qr_code: scannedCode,
        username: user.username,
        password: 'session_authenticated'
      });

      // Set work order data and show process selection
      setWorkOrderData(response.data);
      setShowProcessSelection(true);
      
    } catch (error) {
      setError(error.response?.data?.detail || 'Scan failed');
      
      // Auto-clear error and restart camera after 5 seconds
      setTimeout(() => {
        setError('');
        if (!manualMode && !isDialogShowing.current) {
          startCamera();
        }
      }, 5000);
    }

    setLoading(false);
  };

  // Handle process action (start or end)
  const handleProcessAction = async () => {
    if (!selectedProcess || !workOrderData || loading) return;
    
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post(`${API}/scan/process-action`, {
        qr_code: workOrderData.qr_code,
        username: user.username,
        password: 'session_authenticated',
        process_index: selectedProcess.step_index,
        action: actionType
      });

      setResult(response.data);
      
      // Show confirmation message
      setShowConfirmationMessage(true);
      
      // Reset state after successful action
      setTimeout(() => {
        setResult(null);
        setWorkOrderData(null);
        setSelectedProcess(null);
        setShowProcessSelection(false);
        setQrCode('');
        setShowConfirmationMessage(false);
        if (!manualMode && !isDialogShowing.current) {
          startCamera();
        }
      }, 3000);
    } catch (error) {
      setError(error.response?.data?.detail || 'Process action failed');
      
      // Auto-clear error after 5 seconds
      setTimeout(() => {
        setError('');
      }, 5000);
    }

    setLoading(false);
  };

  // Handle manual scan
  const handleManualScan = async (e) => {
    e.preventDefault();
    if (!qrCode.trim()) return;
    
    await handleWorkOrderScan(qrCode);
  };

  // Handle confirmation dialog - Yes button
  const handleConfirmScan = async () => {
    setShowConfirmDialog(false);
    isDialogShowing.current = false;
    await handleWorkOrderScan(pendingQrCode);
    setPendingQrCode('');
  };

  // Handle confirmation dialog - No button
  const handleCancelScan = () => {
    setShowConfirmDialog(false);
    isDialogShowing.current = false;
    setPendingQrCode('');
    setQrCode('');
    // Resume scanning
    if (!manualMode) {
      startCamera();
    }
  };

  // Handle process selection
  const handleProcessSelect = (process) => {
    setSelectedProcess(process);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-slate-800 flex flex-col">
      {/* Header with minimal info */}
      <div className="bg-black/20 backdrop-blur-lg border-b border-white/10 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
              <img 
                src="https://customer-assets.emergentagent.com/job_metalops/artifacts/i1dybgg7_Velar%20Makine%20Logo%20SVG.png" 
                alt="Velar Makine Logo" 
                className="h-10 w-10 object-contain"
              />
            <div>
              <h1 className="text-xl font-bold text-white">Velar Makine</h1>
              <p className="text-sm text-gray-300">Operator: {user?.username}</p>
            </div>
          </div>
          <Button 
            onClick={logout} 
            variant="outline" 
            size="sm"
            className="border-white/20 text-white hover:bg-white/10"
          >
            <LogOut className="h-4 w-4 mr-2" />
            Çıkış Yap
          </Button>
        </div>
      </div>

      {/* Main Scanner Interface */}
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="w-full max-w-lg">
          {/* Process Selection View */}
          {showProcessSelection && workOrderData ? (
            <Card className="bg-white/10 backdrop-blur-lg border-white/20 shadow-2xl">
              <CardHeader className="text-center pb-4">
                <div className="mx-auto mb-4 p-4 bg-blue-600/20 rounded-full w-fit">
                  <Factory className="h-12 w-12 text-blue-400" />
                </div>
                <CardTitle className="text-2xl text-white mb-2">
                  İş Emri: {workOrderData.work_order.part_number}
                </CardTitle>
                <CardDescription className="text-gray-300">
                  Mevcut Adım: {workOrderData.work_order.current_step_name} ({workOrderData.work_order.current_step_index + 1}/{workOrderData.work_order.total_steps})
                </CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-6">
                {/* Process Selection */}
                <div>
                  <label className="block text-sm font-medium text-white mb-2">
                    İşlem Adımı Seçin
                  </label>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {workOrderData.processes.map((process) => (
                      <div 
                        key={process.step_index}
                        onClick={() => process.can_start || process.can_end ? handleProcessSelect(process) : null}
                        className={`p-3 rounded-lg border cursor-pointer ${
                          selectedProcess?.step_index === process.step_index 
                            ? 'bg-blue-600/40 border-blue-500' 
                            : process.can_start || process.can_end
                              ? 'bg-white/10 border-white/20 hover:bg-white/20' 
                              : 'bg-white/5 border-white/10 opacity-50 cursor-not-allowed'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="text-xs bg-white/10 rounded-full h-6 w-6 flex items-center justify-center text-white">
                              {process.step_index + 1}
                            </span>
                            <span className="text-white">
                              {process.step_name}
                            </span>
                          </div>
                          <Badge className={`${getStatusColor(process.status)} text-white`}>
                            {process.status.replace('_', ' ').toUpperCase()}
                          </Badge>
                        </div>
                        {(process.can_start || process.can_end) && (
                          <div className="mt-2 text-xs text-blue-300">
                            {process.can_start && process.can_end 
                              ? 'Bu adımı başlatabilir veya bitirebilirsiniz' 
                              : process.can_start 
                                ? 'Bu adımı başlatabilirsiniz' 
                                : 'Bu adımı bitirebilirsiniz'}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
                
                {/* Action Type Selection */}
                {selectedProcess && (
                  <div>
                    <label className="block text-sm font-medium text-white mb-2">
                      İşlem Türü
                    </label>
                    <div className="grid grid-cols-2 gap-3">
                      {selectedProcess.can_start && (
                        <Button
                          type="button"
                          onClick={() => setActionType('start')}
                          className={`h-12 ${actionType === 'start' 
                            ? 'bg-green-600 hover:bg-green-700' 
                            : 'bg-white/10 hover:bg-white/20'}`}
                        >
                          <Play className="h-5 w-5 mr-2" />
                          Başlat
                        </Button>
                      )}
                      {selectedProcess.can_end && (
                        <Button
                          type="button"
                          onClick={() => setActionType('end')}
                          className={`h-12 ${actionType === 'end' 
                            ? 'bg-red-600 hover:bg-red-700' 
                            : 'bg-white/10 hover:bg-white/20'}`}
                        >
                          <Pause className="h-5 w-5 mr-2" />
                          Bitir
                        </Button>
                      )}
                    </div>
                  </div>
                )}
                
                {/* Submit Button */}
                <Button 
                  onClick={handleProcessAction}
                  disabled={!selectedProcess || loading}
                  className="w-full bg-blue-600 hover:bg-blue-700 h-12 mt-4"
                >
                  {loading ? (
                    <>
                      <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent mr-3" />
                      İşleniyor...
                    </>
                  ) : (
                    <>
                      <CheckCircle className="h-5 w-5 mr-2" />
                      İşlemi Onayla
                    </>
                  )}
                </Button>
                
                {/* Cancel Button */}
                <Button 
                  onClick={() => {
                    setWorkOrderData(null);
                    setSelectedProcess(null);
                    setShowProcessSelection(false);
                    if (!manualMode) {
                      startCamera();
                    }
                  }}
                  variant="outline"
                  className="w-full border-white/20 text-white hover:bg-white/10"
                >
                  <X className="h-4 w-4 mr-2" />
                  İptal
                </Button>
              </CardContent>
            </Card>
          ) : (
            <Card className="bg-white/10 backdrop-blur-lg border-white/20 shadow-2xl">
              <CardHeader className="text-center pb-4">
                
                <CardTitle className="text-2xl text-white">
                  Üretim Takip Sistemi <br /> QR Kod Okuyucu 
                </CardTitle>
                <CardDescription className="text-gray-300">
                  {manualMode ? 'Manuel Giriş' : 'Kameraya QR Kodu Taratın'}
                </CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-4">
                {/* Camera Scanner or Manual Mode Toggle */}
                <div className="flex justify-center mb-4">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setManualMode(!manualMode)}
                    className="border-white/20 text-white hover:bg-white/10"
                  >
                    {manualMode ? (
                      <>
                        <Camera className="h-4 w-4 mr-2" />
                        Switch to Camera
                      </>
                    ) : (
                      <>
                        <Scan className="h-4 w-4 mr-2" />
                        Manuel Giriş
                      </>
                    )}
                  </Button>
                </div>

                {/* Camera Scanner */}
                {!manualMode && (
                  <div className="space-y-4">
                    <div className="relative bg-black rounded-lg overflow-hidden" style={{ aspectRatio: '4/3' }}>
                      <video
                        ref={videoRef}
                        className="w-full h-full object-cover"
                        playsInline
                        muted
                      />
                      {!cameraActive && (
                        <div className="absolute inset-0 flex items-center justify-center bg-black/50">
                          <Button
                            onClick={startCamera}
                            className="bg-blue-600 hover:bg-blue-700"
                            disabled={loading}
                          >
                            <Camera className="h-5 w-5 mr-2" />
                            Kamerayı Başlat
                          </Button>
                        </div>
                      )}
                      {cameraActive && (
                        <div className="absolute top-2 right-2">
                          <Button
                            onClick={stopCamera}
                            variant="outline"
                            size="sm"
                            className="bg-black/50 border-white/20 text-white hover:bg-black/70"
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      )}
                    </div>
                    
                    {qrCode && (
                      <div className="text-center">
                        <p className="text-sm text-gray-300">Detected QR Code:</p>
                        <p className="text-white font-mono bg-white/10 p-2 rounded mt-1 break-all">{qrCode}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Manual Entry Mode */}
                {manualMode && (
                  <form onSubmit={handleManualScan} className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-white mb-2">
                        QR Code
                      </label>
                      <Input
                        type="text"
                        placeholder="QR Kodu Elle Girin..."
                        value={qrCode}
                        onChange={(e) => setQrCode(e.target.value)}
                        className="bg-white/10 border-white/20 text-white placeholder:text-gray-400 h-12 text-center font-mono"
                        required
                        autoFocus
                      />
                    </div>
                    
                    <Button 
                      type="submit" 
                      className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 h-12"
                      disabled={loading || !qrCode.trim()}
                    >
                      {loading ? (
                        <>
                          <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent mr-3" />
                          Processing...
                        </>
                      ) : (
                        <>
                          <Scan className="h-5 w-5 mr-2" />
                          Scan QR Code
                        </>
                      )}
                    </Button>
                  </form>
                )}

                {/* Camera Error */}
                {cameraError && (
                  <div className="p-3 bg-yellow-500/20 border border-yellow-500/50 rounded-lg">
                    <div className="flex items-start gap-2 text-yellow-400">
                      <Camera className="h-5 w-5 mt-0.5 flex-shrink-0" />
                      <div>
                        <p className="font-semibold text-sm">Camera Issue</p>
                        <p className="text-xs text-yellow-300 mt-1">{cameraError}</p>
                      </div>
                    </div>
                  </div>
                )}
                
                {/* Success Message */}
                {result && (
                  <div className="p-4 bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-500/50 rounded-lg animate-in fade-in duration-300">
                    <div className="flex items-center gap-3 text-green-400 mb-2">
                      <CheckCircle className="h-6 w-6" />
                      <span className="font-semibold">Success!</span>
                    </div>
                    <div className="space-y-1 text-sm">
                      <p className="text-white font-medium">{result.message}</p>
                      <p className="text-green-200">Process Step: {result.step_name}</p>
                      <p className="text-green-200">Time: {new Date().toLocaleTimeString()}</p>
                    </div>
                  </div>
                )}
                
                {/* Error Message */}
                {error && (
                  <div className="p-4 bg-gradient-to-r from-red-500/20 to-rose-500/20 border border-red-500/50 rounded-lg animate-in fade-in duration-300">
                    <div className="flex items-center gap-2 text-red-400 mb-2">
                      <div className="p-1 bg-red-500/20 rounded-full">
                        <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      </div>
                      <span className="font-semibold text-sm">Error</span>
                    </div>
                    <p className="text-red-200 text-sm">{error}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Confirmation Dialog */}
          {showConfirmDialog && (
            <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
              <div className="bg-white/10 backdrop-blur-lg border border-white/20 rounded-2xl p-6 w-full max-w-sm animate-in fade-in zoom-in duration-300">
                <div className="text-center mb-6">
                  <img 
                    src="https://customer-assets.emergentagent.com/job_metalops/artifacts/i1dybgg7_Velar%20Makine%20Logo%20SVG.png" 
                    alt="Velar Makine Logo" 
                    className="h-10 w-10 object-contain mx-auto"
                  />
                  <h3 className="text-xl font-bold text-white mb-2">QR Kod Tespit Edildi!</h3>
                  <p className="text-gray-300 text-sm mb-4">Bu kod için işlem yapılsın mı?</p>
                  <div className="bg-white/5 rounded-lg p-3 mb-4">
                    <p className="text-xs text-gray-400 mb-1">Tespit edilen kod:</p>
                    <p className="text-white font-mono text-sm break-all">{pendingQrCode}</p>
                  </div>
                </div>
                
                <div className="flex gap-3">
                  <Button
                    onClick={handleCancelScan}
                    variant="outline"
                    className="flex-1 border-white/20 text-white hover:bg-white/10 h-12"
                    disabled={loading}
                  >
                    <X className="h-4 w-4 mr-2" />
                    Hayır
                  </Button>
                  <Button
                    onClick={handleConfirmScan}
                    className="flex-1 bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 h-12"
                    disabled={loading}
                  >
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2" />
                        İşleniyor...
                      </>
                    ) : (
                      <>
                        <CheckCircle className="h-4 w-4 mr-2" />
                        Evet
                      </>
                    )}
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* New Confirmation Message after işlemi onayla button click */}
          {showConfirmationMessage && (
            <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
              <div className="bg-white/10 backdrop-blur-lg border border-white/20 rounded-2xl p-6 w-full max-w-sm animate-in fade-in zoom-in duration-300">
                <div className="text-center mb-6">
                  <div className="mx-auto mb-4 p-4 bg-green-600/20 rounded-full w-fit">
                    <CheckCircle className="h-12 w-12 text-green-400" />
                  </div>
                  <h3 className="text-xl font-bold text-white mb-2">İşlem Onaylanmıştır</h3>
                  <p className="text-gray-300 text-sm">
                    İşleminiz başarıyla sisteme kaydedilmiştir.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// QR Scanner Component for Managers/Admins
const QRScanner = () => {
  const [qrCode, setQrCode] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  
  // New state for process selection
  const [workOrderData, setWorkOrderData] = useState(null);
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [actionType, setActionType] = useState('start');
  const [showProcessSelection, setShowProcessSelection] = useState(false);

  // Handle scanning a work order QR code
  const handleWorkOrderScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);
    setWorkOrderData(null);
    setShowProcessSelection(false);

    try {
      const response = await axios.post(`${API}/scan/work-order`, {
        qr_code: qrCode,
        username,
        password
      });

      // Set work order data and show process selection
      setWorkOrderData(response.data);
      setShowProcessSelection(true);
      
      // Clear form fields
      setQrCode('');
      
    } catch (error) {
      setError(error.response?.data?.detail || 'Scan failed');
    }

    setLoading(false);
  };

  // Handle process action (start or end)
  const handleProcessAction = async (e) => {
    e.preventDefault();
    if (!selectedProcess || !workOrderData || loading) return;
    
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post(`${API}/scan/process-action`, {
        qr_code: workOrderData.qr_code,
        username,
        password,
        process_index: selectedProcess.step_index,
        action: actionType
      });

      setResult(response.data);
      
      // Reset process selection
      setSelectedProcess(null);
      setWorkOrderData(null);
      setShowProcessSelection(false);
      setUsername('');
      setPassword('');
      
    } catch (error) {
      setError(error.response?.data?.detail || 'Process action failed');
    }

    setLoading(false);
  };

  return (
    <div className="max-w-md mx-auto space-y-6">
      {!showProcessSelection ? (
        <Card className="bg-white/5 backdrop-blur-lg border-white/10">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Scan className="h-5 w-5" />
              QR Kod Okuyucu
            </CardTitle>
            <CardDescription className="text-gray-300">
              İş emri QR kodunu tarayarak işlem yapabilirsiniz
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleWorkOrderScan} className="space-y-4">
              <div>
                <Input
                  type="text"
                  placeholder="QR Kodu Manuel Olarak Girin"
                  value={qrCode}
                  onChange={(e) => setQrCode(e.target.value)}
                  className="bg-white/10 border-white/20 text-white placeholder:text-gray-400"
                  required
                />
              </div>
              
              <div>
                <Input
                  type="text"
                  placeholder="Kullanıcı Adı"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="bg-white/10 border-white/20 text-white placeholder:text-gray-400"
                  required
                />
              </div>
              
              <div>
                <Input
                  type="password"
                  placeholder="Şifre"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="bg-white/10 border-white/20 text-white placeholder:text-gray-400"
                  required
                />
              </div>
              
              <Button 
                type="submit" 
                className="w-full bg-blue-600 hover:bg-blue-700"
                disabled={loading}
              >
                {loading ? 'Processing...' : (
                  <>
                    <Scan className="h-4 w-4 mr-2" />
                    QR Kodu Tara
                  </>
                )}
              </Button>
            </form>
          </CardContent>
        </Card>
      ) : (
        <Card className="bg-white/5 backdrop-blur-lg border-white/10">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-white">İş Emri: {workOrderData.work_order.part_number}</CardTitle>
              <Badge className={`${getStatusColor(workOrderData.work_order.status)} text-white`}>
                {workOrderData.work_order.status.replace('_', ' ').toUpperCase()}
              </Badge>
            </div>
            <CardDescription className="text-gray-300">
              Mevcut Adım: {workOrderData.work_order.current_step_name} ({workOrderData.work_order.current_step_index + 1}/{workOrderData.work_order.total_steps})
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleProcessAction} className="space-y-4">
              {/* Process Selection */}
              <div>
                <label className="block text-sm font-medium text-white mb-2">
                  İşlem Adımı Seçin
                </label>
                <Select 
                  value={selectedProcess?.step_index.toString() || ''} 
                  onValueChange={(value) => {
                    const process = workOrderData.processes.find(p => p.step_index.toString() === value);
                    setSelectedProcess(process);
                    // Auto-select action type based on what's available
                    if (process) {
                      if (process.can_start) setActionType('start');
                      else if (process.can_end) setActionType('end');
                    }
                  }}
                >
                  <SelectTrigger className="bg-white/10 border-white/20 text-white">
                    <SelectValue placeholder="İşlem adımı seçin" />
                  </SelectTrigger>
                  <SelectContent>
                    {workOrderData.processes.map((process) => (
                      <SelectItem 
                        key={process.step_index} 
                        value={process.step_index.toString()}
                        disabled={!process.can_start && !process.can_end}
                      >
                        {process.step_name} ({process.status})
                        {process.can_start && process.can_end 
                          ? ' - Başlatılabilir/Bitirilebilir' 
                          : process.can_start 
                            ? ' - Başlatılabilir' 
                            : process.can_end 
                              ? ' - Bitirilebilir' 
                              : ' - İşlem yapılamaz'}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              
              {/* Action Type Selection */}
              {selectedProcess && (
                <div>
                  <label className="block text-sm font-medium text-white mb-2">
                    İşlem Türü
                  </label>
                  <Select 
                    value={actionType} 
                    onValueChange={setActionType}
                    disabled={!(selectedProcess.can_start && selectedProcess.can_end)}
                  >
                    <SelectTrigger className="bg-white/10 border-white/20 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {selectedProcess.can_start && (
                        <SelectItem value="start">Başlat</SelectItem>
                      )}
                      {selectedProcess.can_end && (
                        <SelectItem value="end">Bitir</SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                </div>
              )}
              
              {/* Submit Button */}
              <Button 
                type="submit" 
                className="w-full bg-blue-600 hover:bg-blue-700"
                disabled={loading || !selectedProcess}
              >
                {loading ? 'Processing...' : (
                  <>
                    {actionType === 'start' ? <Play className="h-4 w-4 mr-2" /> : <Pause className="h-4 w-4 mr-2" />}
                    {actionType === 'start' ? 'İşlemi Başlat' : 'İşlemi Bitir'}
                  </>
                )}
              </Button>
              
              {/* Cancel Button */}
              <Button 
                type="button"
                onClick={() => {
                  setWorkOrderData(null);
                  setSelectedProcess(null);
                  setShowProcessSelection(false);
                }}
                variant="outline"
                className="w-full border-white/20 text-white hover:bg-white/10"
              >
                <X className="h-4 w-4 mr-2" />
                İptal
              </Button>
            </form>
          </CardContent>
        </Card>
      )}
      
      {result && (
        <div className="mt-4 p-4 bg-green-500/20 border border-green-500/50 rounded-lg">
          <div className="flex items-center gap-2 text-green-400 mb-2">
            <CheckCircle className="h-5 w-5" />
            <span className="font-medium">Success</span>
          </div>
          <p className="text-white text-sm">{result.message}</p>
          <p className="text-gray-300 text-sm">Step: {result.step_name}</p>
          <p className="text-gray-300 text-sm">Operator: {result.operator}</p>
        </div>
      )}
      
      {error && (
        <div className="mt-4 p-4 bg-red-500/20 border border-red-500/50 rounded-lg">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}
    </div>
  );
};

// Dashboard Component
const Dashboard = () => {
  const [dashboardData, setDashboardData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const response = await axios.get(`${API}/dashboard/overview`);
      setDashboardData(response.data);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-white">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Üretim Takip Paneli</h2>
        <Button onClick={fetchDashboardData} variant="outline" size="sm" className="bg-gray-300 hover:bg-gray-400 text-gray-800">
          Refresh
        </Button>
      </div>
      
      <div className="grid gap-4">
        {dashboardData.map((item, index) => (
          <Card key={index} className="bg-white/5 backdrop-blur-lg border-white/10">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-white text-lg">
                  Part: {item.part.part_number}
                </CardTitle>
                <Badge className={`${getStatusColor(item.part.status)} text-white`}>
                  <div className="flex items-center gap-1">
                    {getStatusIcon(item.part.status)}
                    {item.part.status.replace('_', ' ').toUpperCase()}
                  </div>
                </Badge>
              </div>
              <CardDescription className="text-gray-300">
                Project: {item.project.name}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <span className="text-gray-300">Current Step:</span>
                <span className="text-white font-medium">{item.current_step}</span>
              </div>
              <div className="mt-4">
                <div className="flex justify-between text-sm text-gray-400 mb-2">
                  <span>Progress</span>
                  <span>{item.part.current_step_index + 1} / {item.total_steps}</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div 
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ 
                      width: `${item.progress_percentage}%` 
                    }}
                  ></div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
        
        {dashboardData.length === 0 && (
          <Card className="bg-white/5 backdrop-blur-lg border-white/10">
            <CardContent className="py-8 text-center">
              <p className="text-gray-400">No parts in production yet</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

// Projects Component
const Projects = () => {
  const [projects, setProjects] = useState([]);
  const [projectsWithParts, setProjectsWithParts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedProject, setSelectedProject] = useState('');
  const [newPartNumber, setNewPartNumber] = useState('');
  const [newProjectName, setNewProjectName] = useState('');
  const [deleteItemType, setDeleteItemType] = useState('project'); // 'project' or 'part'
  const [deleteSelectedId, setDeleteSelectedId] = useState('');
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteItemName, setDeleteItemName] = useState('');
  const [selectedSteps, setSelectedSteps] = useState([]);
  const [showStepSelector, setShowStepSelector] = useState(false);

  // Available manufacturing steps
  const availableSteps = [
    "1-DEPO",
    "2-LAZER KESİM", 
    "3-BÜKÜM",
    "4-KAYNAK",
    "5-CNC FREZE",
    "6-CNC TORNA",
    "7-TESVİYE ÇAPAK ALMA",
    "8-KLAVUZ ÇEKME",
    "9-KESİM (Şerit Daire Testere)",
    "10-PRES ŞİŞİRME ÇÖKERTME KALIP",
    "11-MATKAP",
    "12-KUMLAMA",
    "13-YAŞ BOYA",
    "14-MONTAJ",
    "15-DIŞ OPERASYON ISIL İŞLEME SEVK",
    "16-DIŞ OPERASYON KAPLAMA İŞLEMİNE SEVK",
    "17-KAPLAMA GİRİŞ MUAYENE",
    "18-DIŞ OPERASYON YAŞ BOYA İŞLEMİNE SEVK",
    "19-YAŞ BOYA GİRİŞ MUAYENE",
    "20-DIŞ OPERASYON TOZ BOYA İŞLEMİNE SEVK",
    "21-TOZ BOYA GİRİŞ MUAYENE",
    "22-DIŞ İMALATA SEVK",
    "23-DIŞ İMALAT GİRİŞ MUAYENE",
    "24-DIŞ OPERASYON KESİM GİRİŞ MUAYENE",
    "25-KAYNAĞINDA MUAYENE",
    "26-SMLE GİRİŞ",
    "27-SON MUAYENE MÜŞTERİ SEVK",
    "28-YARI MAMÜL",
    "29-PUNTA KAYNAK",
    "30-PLAZMA LAZER SU JETİ SEVK",
    "31-ASTAR BOYA",
    "32-KAYNAK AĞZI AÇMA",
    "33-TAŞLAMA DOĞRULTMA",
    "34-ARA MUAYENE"
  ];

  useEffect(() => {
    fetchProjectsWithParts();
  }, []);

  const fetchProjects = async () => {
    try {
      const response = await axios.get(`${API}/projects`);
      setProjects(response.data);
    } catch (error) {
      console.error('Failed to fetch projects:', error);
    }
  };

  const fetchProjectsWithParts = async () => {
    try {
      const response = await axios.get(`${API}/projects`);
      const projects = response.data;
      setProjects(projects);
      
      // Fetch parts for each project
      const projectsWithPartsPromises = projects.map(async (project) => {
        try {
          const partsResponse = await axios.get(`${API}/projects/${project.id}/parts`);
          return {
            ...project,
            parts: partsResponse.data
          };
        } catch (error) {
          console.error(`Failed to fetch parts for project ${project.id}:`, error);
          return {
            ...project,
            parts: []
          };
        }
      });
      
      const projectsWithPartsData = await Promise.all(projectsWithPartsPromises);
      setProjectsWithParts(projectsWithPartsData);
    } catch (error) {
      console.error('Failed to fetch projects:', error);
    } finally {
      setLoading(false);
    }
  };

  const createPart = async (e) => {
    e.preventDefault();
    if (!newPartNumber) return;

    // Validation: Project must be selected
    if (!selectedProject) {
      alert('Lütfen bir proje seçin. İş emri mutlaka bir projeye bağlı olmalıdır.');
      return;
    }

    // Validation: At least one process step must be selected
    if (selectedSteps.length === 0) {
      alert('En az bir süreç adımı seçmelisiniz! "Adım Ekle" butonunu kullanarak süreç adımlarını ekleyin.');
      return;
    }

    try {
      // Create the work order within the selected project using custom steps
      await axios.post(`${API}/parts`, {
        part_number: newPartNumber,
        project_id: selectedProject,
        process_steps: selectedSteps
      });
      
      setNewPartNumber('');
      setSelectedProject('');
      setSelectedSteps([]);
      setShowStepSelector(false);
      fetchProjectsWithParts();
    } catch (error) {
      console.error('Failed to create part:', error);
      if (error.response?.data?.detail) {
        alert(`İş emri oluşturulurken hata oluştu: ${error.response.data.detail}`);
      } else {
        alert('İş emri oluşturulurken hata oluştu. Lütfen tekrar deneyin.');
      }
    }
  };

  const addStep = (step) => {
    setSelectedSteps([...selectedSteps, step]);
  };

  const removeStep = (index) => {
    const newSteps = selectedSteps.filter((_, i) => i !== index);
    setSelectedSteps(newSteps);
  };

  const moveStepUp = (index) => {
    if (index === 0) return;
    const newSteps = [...selectedSteps];
    [newSteps[index - 1], newSteps[index]] = [newSteps[index], newSteps[index - 1]];
    setSelectedSteps(newSteps);
  };

  const moveStepDown = (index) => {
    if (index === selectedSteps.length - 1) return;
    const newSteps = [...selectedSteps];
    [newSteps[index], newSteps[index + 1]] = [newSteps[index + 1], newSteps[index]];
    setSelectedSteps(newSteps);
  };

  const createProject = async (e) => {
    e.preventDefault();
    if (!newProjectName.trim()) return;

    try {
      await axios.post(`${API}/projects`, {
        name: newProjectName,
        description: `Project created: ${newProjectName}`,
        process_steps: [
          "Initial Quality Control",
          "Machining (CNC)", 
          "Welding",
          "Painting",
          "Final Quality Control"
        ]
      });
      
      setNewProjectName('');
      fetchProjects();
      fetchProjectsWithParts();
    } catch (error) {
      console.error('Failed to create project:', error);
    }
  };

  const handleDeleteClick = () => {
    if (!deleteSelectedId) return;
    
    let itemName = '';
    if (deleteItemType === 'project') {
      const project = projects.find(p => p.id === deleteSelectedId);
      itemName = project?.name || '';
    } else {
      // Find part across all projects
      let part = null;
      for (const project of projectsWithParts) {
        part = project.parts?.find(p => p.id === deleteSelectedId);
        if (part) break;
      }
      itemName = part?.part_number || '';
    }
    
    setDeleteItemName(itemName);
    setShowDeleteConfirm(true);
  };

  const confirmDelete = async () => {
    try {
      if (deleteItemType === 'project') {
        await axios.delete(`${API}/projects/${deleteSelectedId}`);
        fetchProjects();
        fetchProjectsWithParts(); // Refresh projects with parts as well since they might be affected
      } else {
        await axios.delete(`${API}/parts/${deleteSelectedId}`);
        fetchProjectsWithParts();
      }
      
      setShowDeleteConfirm(false);
      setDeleteSelectedId('');
      setDeleteItemName('');
    } catch (error) {
      console.error('Failed to delete item:', error);
    }
  };

  const cancelDelete = () => {
    setShowDeleteConfirm(false);
    setDeleteItemName('');
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-white">Loading projects...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-white">Projeler ve İş Emirleri</h2>
      
      {/* New Project Creation Section */}
      <Card className="bg-white/5 backdrop-blur-lg border-white/10">
        <CardHeader>
          <CardTitle className="text-white">Yeni Proje Ekle</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={createProject} className="space-y-4">
            <div>
              <Input
                type="text"
                placeholder="Yeni Proje Adı"
                value={newProjectName}
                onChange={(e) => setNewProjectName(e.target.value)}
                className="bg-white/10 border-white/20 text-white placeholder:text-gray-400"
                required
              />
            </div>
            
            <Button type="submit" className="bg-green-600 hover:bg-green-700">
              Proje Oluştur
            </Button>
          </form>
        </CardContent>
      </Card>
      
      <Card className="bg-white/5 backdrop-blur-lg border-white/10">
        <CardHeader>
          <CardTitle className="text-white">Yeni İş Emri Ekle</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={createPart} className="space-y-4">
            <div>
              <div className="mb-2">
                <label className="text-sm font-medium text-white">Proje Seçin</label>
                <p className="text-xs text-gray-400">İş emri mutlaka bir projeye bağlı olmalıdır</p>
              </div>
              <Select value={selectedProject} onValueChange={setSelectedProject}>
                <SelectTrigger className="bg-white/10 border-white/20 text-white">
                  <SelectValue placeholder="Proje Seçin" />
                </SelectTrigger>
                <SelectContent>
                  {projects.map(project => (
                    <SelectItem key={project.id} value={project.id}>
                      {project.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            
            <div>
              <Input
                type="text"
                placeholder="İş Emri No"
                value={newPartNumber}
                onChange={(e) => setNewPartNumber(e.target.value)}
                className="bg-white/10 border-white/20 text-white placeholder:text-gray-400"
                required
              />
            </div>
            
            {/* Step Selection Section */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium text-white">İş Akış Adımları</label>
                  <p className="text-xs text-gray-400 mt-1">En az bir adım seçmelisiniz</p>
                </div>
                <Button
                  type="button"
                  onClick={() => setShowStepSelector(!showStepSelector)}
                  variant="outline"
                  size="sm"
                  className="border-white/20 text-white hover:bg-white/10"
                >
                  <Plus className="h-4 w-4 mr-1" />
                  Adım Ekle
                </Button>
              </div>
              
              {/* Step Selector Dropdown */}
              {showStepSelector && (
                <Card className="bg-white/5 border-white/20">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm text-white">Mevcut Adımları Seçin</CardTitle>
                  </CardHeader>
                  <CardContent className="pt-2">
                    <div className="grid grid-cols-1 gap-2 max-h-60 overflow-y-auto">
                      {availableSteps.map((step, index) => (
                        <Button
                          key={index}
                          type="button"
                          onClick={() => addStep(step)}
                          variant="outline"
                          size="sm"
                          className="justify-start text-left border-white/20 text-white hover:bg-white/10 text-xs"
                        >
                          <Plus className="h-3 w-3 mr-2" />
                          {step}
                        </Button>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
              
              {/* Selected Steps Display */}
              {selectedSteps.length > 0 && (
                <Card className="bg-blue-600/5 border-blue-500/30">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm text-blue-300 flex items-center">
                      <List className="h-4 w-4 mr-2" />
                      Seçili Adımlar ({selectedSteps.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="pt-2">
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {selectedSteps.map((step, index) => (
                        <div key={index} className="flex items-center justify-between bg-white/5 rounded p-2">
                          <div className="flex items-center gap-2">
                            <span className="text-xs bg-blue-600/20 text-blue-300 px-2 py-1 rounded">
                              {index + 1}
                            </span>
                            <span className="text-sm text-white">{step}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <Button
                              type="button"
                              onClick={() => moveStepUp(index)}
                              disabled={index === 0}
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0 text-gray-400 hover:text-white"
                            >
                              <ChevronUp className="h-3 w-3" />
                            </Button>
                            <Button
                              type="button"
                              onClick={() => moveStepDown(index)}
                              disabled={index === selectedSteps.length - 1}
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0 text-gray-400 hover:text-white"
                            >
                              <ChevronDown className="h-3 w-3" />
                            </Button>
                            <Button
                              type="button"
                              onClick={() => removeStep(index)}
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0 text-red-400 hover:text-red-300"
                            >
                              <X className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
            
            <Button type="submit" className="bg-green-600 hover:bg-green-700">
              İş Emri Oluştur
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Delete Section - Moved directly below the "Yeni İş Emri Ekle" box */}
      <Card className="bg-white/5 backdrop-blur-lg border-white/10 border-red-500/30">
        <CardHeader>
          <CardTitle className="text-white">Proje Veya İş Emrini Sil</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <Select value={deleteItemType} onValueChange={(value) => {
                setDeleteItemType(value);
                setDeleteSelectedId(''); // Clear selection when switching types
              }}>
                <SelectTrigger className="bg-white/10 border-white/20 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="project">Proje Sil</SelectItem>
                  <SelectItem value="part">İş Emri Sil</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div>
              <Select value={deleteSelectedId} onValueChange={setDeleteSelectedId}>
                <SelectTrigger className="bg-white/10 border-white/20 text-white">
                  <SelectValue placeholder={deleteItemType === 'project' ? 'Proje Seçin' : 'İş Emri Seçin'} />
                </SelectTrigger>
                <SelectContent>
                  {deleteItemType === 'project' 
                    ? projects.map(project => (
                        <SelectItem key={project.id} value={project.id}>
                          {project.name}
                        </SelectItem>
                      ))
                    : projectsWithParts.flatMap(project => 
                        project.parts?.map(part => (
                          <SelectItem key={part.id} value={part.id}>
                            {part.part_number} ({project.name})
                          </SelectItem>
                        )) || []
                      )
                  }
                </SelectContent>
              </Select>
            </div>
            
            <Button 
              onClick={handleDeleteClick}
              disabled={!deleteSelectedId}
              className="bg-red-600 hover:bg-red-700"
            >
              Sil
            </Button>
          </div>
        </CardContent>
      </Card>
      
      
      {/* Projects with their Work Orders - Hierarchical Display */}
      <div className="space-y-6">
        <h3 className="text-xl font-bold text-white">Projeler ve İş Emirleri</h3>
        
        {projectsWithParts.map(project => (
          <Card key={project.id} className="bg-white/5 backdrop-blur-lg border-white/10">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-white text-lg">{project.name}</CardTitle>
                  <CardDescription className="text-gray-300">
                    {project.description}
                  </CardDescription>
                  <div className="mt-2">
                    <Badge className="bg-blue-600/20 text-blue-300 border-blue-600/30">
                      {project.parts?.length || 0} İş Emri
                    </Badge>
                  </div>
                </div>
              </div>
            </CardHeader>
            
            {/* Work Orders within this Project */}
            {project.parts && project.parts.length > 0 && (
              <CardContent>
                <div className="space-y-3">
                  <h4 className="text-sm font-medium text-white mb-3">İş Emirleri:</h4>
                  <div className="grid gap-3">
                    {project.parts.map(part => (
                      <div key={part.id} className="bg-white/5 rounded-lg p-3 border border-white/10">
                        <div className="flex items-center justify-between">
                          <div>
                            <span className="text-white font-medium">{part.part_number}</span>
                            <div className="text-sm text-gray-300 mt-1">
                              Adım: {part.current_step_index + 1} / {part.total_steps}
                            </div>
                          </div>
                          <Badge className={`${getStatusColor(part.status)} text-white`}>
                            {part.status.replace('_', ' ').toUpperCase()}
                          </Badge>
                        </div>
                        <div className="mt-2 text-xs text-gray-400">
                          Oluşturuldu: {new Date(part.created_at).toLocaleDateString('tr-TR')}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            )}
            
            {/* Empty state for projects with no work orders */}
            {(!project.parts || project.parts.length === 0) && (
              <CardContent>
                <div className="text-center py-4 text-gray-400">
                  Bu projede henüz iş emri bulunmuyor
                </div>
              </CardContent>
            )}
          </Card>
        ))}
        
        {/* Empty state for no projects */}
        {projectsWithParts.length === 0 && !loading && (
          <Card className="bg-white/5 backdrop-blur-lg border-white/10">
            <CardContent className="py-8 text-center">
              <p className="text-gray-400">Henüz proje bulunmuyor</p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Confirmation Modal */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-gray-800 p-6 rounded-lg shadow-xl max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-white mb-4">
              Bu dosyayı '{deleteItemName}' silmek istediğinize emin misiniz?
            </h3>
            <div className="flex gap-3 justify-end">
              <Button 
                onClick={cancelDelete}
                variant="outline"
                className="border-gray-500 text-gray-300 hover:bg-gray-700"
              >
                İptal Et
              </Button>
              <Button 
                onClick={confirmDelete}
                className="bg-red-600 hover:bg-red-700"
              >
                Sil
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// QR Codes Component  
const QRCodes = () => {
  const [parts, setParts] = useState([]);
  const [selectedPart, setSelectedPart] = useState('');
  const [qrCodes, setQrCodes] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchParts();
  }, []);

  const fetchParts = async () => {
    try {
      const response = await axios.get(`${API}/parts`);
      setParts(response.data);
    } catch (error) {
      console.error('Failed to fetch parts:', error);
    }
  };

  const fetchQRCodes = async (partId) => {
    setLoading(true);
    try {
      const response = await axios.get(`${API}/parts/${partId}/qr-codes`);
      setQrCodes(response.data);
    } catch (error) {
      console.error('Failed to fetch QR codes:', error);
    } finally {
      setLoading(false);
    }
  };

  const handlePartChange = (partId) => {
    setSelectedPart(partId);
    if (partId) {
      fetchQRCodes(partId);
    } else {
      setQrCodes([]);
    }
  };

  // Download a PDF containing the QR code for the selected work order
  const handleDownloadPdf = async () => {
    if (!selectedPart) return;
    try {
      const response = await axios.get(`${API}/parts/${selectedPart}/qr-codes/pdf`, {
        responseType: 'blob'
      });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      // Attempt to extract filename from Content-Disposition header
      let filename = `Is_Emri_QR_Kodu.pdf`; 
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to download PDF:', error);
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-white">QR Kodlar</h2>
      
      <Card className="bg-white/5 backdrop-blur-lg border-white/10">
        <CardHeader>
          <CardTitle className="text-white">İş Emri İçin QR Kod Üret</CardTitle>
          <CardDescription className="text-gray-300">
            Her iş emri için tek bir QR kod oluşturulur. Bu kod, iş emrinin tüm süreçleri boyunca kullanılabilir.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Select value={selectedPart} onValueChange={handlePartChange}>
            <SelectTrigger className="bg-white/10 border-white/20 text-white">
              <SelectValue placeholder="İş Emri Seçin" />
            </SelectTrigger>
            <SelectContent>
              {parts.map(part => (
                <SelectItem key={part.id} value={part.id}>
                  {part.part_number}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      {/* PDF Download Button */}
      {selectedPart && qrCodes.length > 0 && (
        <div className="flex justify-end">
          <Button
            onClick={handleDownloadPdf}
            className="mt-4 bg-blue-600 hover:bg-blue-700"
          >
            <Download className="h-4 w-4 mr-2" />
            PDF İndir
          </Button>
        </div>
      )}
      
      {loading && (
        <div className="text-center text-white">QR kodları yükleniyor...</div>
      )}
      
      <div className="grid gap-6">
        {qrCodes.map((qrData, index) => (
          <Card key={index} className="bg-white/5 backdrop-blur-lg border-white/10">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-white">İş Emri: {qrData.work_order.part_number}</CardTitle>
                  <CardDescription className="text-gray-300 mt-1">
                    Mevcut Adım: {qrData.work_order.current_step_name} ({qrData.work_order.current_step_index + 1}/{qrData.work_order.total_steps})
                  </CardDescription>
                </div>
                <Badge className={`${getStatusColor(qrData.work_order.status)} text-white`}>
                  {qrData.work_order.status.replace('_', ' ').toUpperCase()}
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col items-center justify-center">
                <h4 className="text-blue-400 font-medium mb-4">İş Emri QR Kodu</h4>
                <div className="bg-white p-6 rounded-lg inline-block">
                  <img src={qrData.qr_code.image} alt="Work Order QR" className="w-48 h-48" />
                </div>
                <p className="text-xs text-gray-400 mt-4 break-all">{qrData.qr_code.code}</p>
                
                <div className="mt-8 w-full">
                  <h4 className="text-white font-medium mb-2">İş Akış Adımları:</h4>
                  <div className="space-y-2 mt-4">
                    {qrData.process_steps.map((step, stepIndex) => (
                      <div 
                        key={stepIndex} 
                        className={`p-3 rounded-lg border ${
                          step.step_index === qrData.work_order.current_step_index 
                            ? 'bg-blue-600/20 border-blue-500/50' 
                            : step.status === 'completed' 
                              ? 'bg-green-600/20 border-green-500/50' 
                              : 'bg-white/5 border-white/20'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="text-xs bg-white/10 rounded-full h-6 w-6 flex items-center justify-center text-white">
                              {step.step_index + 1}
                            </span>
                            <span className={`${
                              step.step_index === qrData.work_order.current_step_index 
                                ? 'text-blue-300 font-medium' 
                                : step.status === 'completed' 
                                  ? 'text-green-300' 
                                  : 'text-white'
                            }`}>
                              {step.step_name}
                            </span>
                          </div>
                          <Badge className={`${getStatusColor(step.status)} text-white`}>
                            {step.status.replace('_', ' ').toUpperCase()}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

// Veriler (Data) Component - Manager Only
const Veriler = () => {
  const [durationData, setDurationData] = useState([]);
  const [filteredData, setFilteredData] = useState([]);
  const [projects, setProjects] = useState([]);
  const [parts, setParts] = useState([]);
  const [selectedProject, setSelectedProject] = useState('');
  const [selectedPart, setSelectedPart] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingProjects, setLoadingProjects] = useState(false);
  const [loadingParts, setLoadingParts] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchProjects();
    fetchDurationData();
  }, []);

  useEffect(() => {
    if (selectedProject) {
      fetchProjectParts(selectedProject);
      setSelectedPart(''); // Reset part selection when project changes
    } else {
      setParts([]);
      setSelectedPart('');
    }
  }, [selectedProject]);

  useEffect(() => {
    filterData();
  }, [durationData, selectedProject, selectedPart]);

  const fetchProjects = async () => {
    setLoadingProjects(true);
    try {
      const response = await axios.get(`${API}/projects`);
      setProjects(response.data);
    } catch (error) {
      console.error('Failed to fetch projects:', error);
    } finally {
      setLoadingProjects(false);
    }
  };

  const fetchProjectParts = async (projectId) => {
    setLoadingParts(true);
    try {
      const response = await axios.get(`${API}/projects/${projectId}/parts`);
      setParts(response.data);
    } catch (error) {
      console.error('Failed to fetch project parts:', error);
      setParts([]);
    } finally {
      setLoadingParts(false);
    }
  };

  const fetchDurationData = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.get(`${API}/veriler`);
      setDurationData(response.data);
    } catch (error) {
      console.error('Failed to fetch duration data:', error);
      if (error.response?.status === 403) {
        setError('Bu sayfaya erişim yetkiniz bulunmamaktadır. Sadece yöneticiler bu verileri görüntüleyebilir.');
      } else {
        setError('Veri yüklenirken bir hata oluştu.');
      }
    } finally {
      setLoading(false);
    }
  };

  const filterData = () => {
    if (!selectedProject || !selectedPart) {
      setFilteredData([]);
      return;
    }

    const selectedProjectData = projects.find(p => p.id === selectedProject);
    const selectedPartData = parts.find(p => p.id === selectedPart);

    if (!selectedProjectData || !selectedPartData) {
      setFilteredData([]);
      return;
    }

    const filtered = durationData.filter(item => 
      item.project_name === selectedProjectData.name && 
      item.part_number === selectedPartData.part_number
    );

    setFilteredData(filtered);
  };

  const formatDuration = (minutes) => {
    if (minutes < 1) {
      return `${Math.round(minutes * 60)} saniye`;
    }
    return `${minutes.toFixed(1)} dakika`;
  };

  const formatDateTime = (dateString) => {
    return new Date(dateString).toLocaleString('tr-TR');
  };

  if (error) {
    return (
      <div className="space-y-6">
        <h2 className="text-2xl font-bold text-white">Veriler</h2>
        <Card className="bg-red-500/10 backdrop-blur-lg border-red-500/20">
          <CardContent className="pt-6">
            <p className="text-red-300 text-center">{error}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Veriler</h2>
        <Button 
          onClick={fetchDurationData} 
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-700"
        >
          {loading ? 'Yenileniyor...' : 'Verileri Yenile'}
        </Button>
      </div>

      {/* Filter Controls */}
      <Card className="bg-white/5 backdrop-blur-lg border-white/10">
        <CardHeader>
          <CardTitle className="text-white">Filtreler</CardTitle>
          <CardDescription className="text-gray-300">
            Proje ve iş emri seçerek verileri filtreleyebilirsiniz
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-4">
            {/* Project Dropdown */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">Proje Seçin</label>
              <select
                value={selectedProject}
                onChange={(e) => setSelectedProject(e.target.value)}
                disabled={loadingProjects}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">
                  {loadingProjects ? 'Projeler yükleniyor...' : 'Proje seçin'}
                </option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id} className="bg-gray-800 text-white">
                    {project.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Work Order (Part) Dropdown */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-300">İş Emri Seçin</label>
              <select
                value={selectedPart}
                onChange={(e) => setSelectedPart(e.target.value)}
                disabled={!selectedProject || loadingParts}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-50"
              >
                <option value="">
                  {!selectedProject 
                    ? 'Önce proje seçin' 
                    : loadingParts 
                      ? 'İş emirleri yükleniyor...' 
                      : 'İş emri seçin'
                  }
                </option>
                {parts.map((part) => (
                  <option key={part.id} value={part.id} className="bg-gray-800 text-white">
                    {part.part_number}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {selectedProject && selectedPart && (
            <div className="mt-4 p-3 bg-blue-500/10 border border-blue-500/20 rounded-md">
              <p className="text-blue-300 text-sm">
                <span className="font-medium">Seçili Proje:</span> {projects.find(p => p.id === selectedProject)?.name}
                <span className="mx-2">•</span>
                <span className="font-medium">Seçili İş Emri:</span> {parts.find(p => p.id === selectedPart)?.part_number}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
      
      {/* Data Display */}
      <Card className="bg-white/5 backdrop-blur-lg border-white/10">
        <CardHeader>
          <CardTitle className="text-white">İşlem Süreleri</CardTitle>
          <CardDescription className="text-gray-300">
            {selectedProject && selectedPart 
              ? 'Seçili proje ve iş emri için process süreleri'
              : 'Verileri görüntülemek için yukarıdan proje ve iş emri seçin'
            }
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center text-white py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white mx-auto mb-4"></div>
              Veriler yükleniyor...
            </div>
          ) : !selectedProject || !selectedPart ? (
            <div className="text-center text-gray-400 py-8">
              <div className="mb-4">
                <svg className="w-16 h-16 mx-auto text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
                </svg>
              </div>
              <p className="text-lg font-medium mb-2">Filtre Seçimi Gerekli</p>
              <p>Verileri görüntülemek için yukarıdan proje ve iş emri seçin.</p>
            </div>
          ) : filteredData.length === 0 ? (
            <div className="text-center text-gray-400 py-8">
              <div className="mb-4">
                <svg className="w-16 h-16 mx-auto text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <p className="text-lg font-medium mb-2">Veri Bulunamadı</p>
              <p>Seçili proje ve iş emri için henüz tamamlanmış işlem verisi bulunmuyor.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredData.map((item) => (
                <Card key={item.id} className="bg-white/5 border-white/10">
                  <CardContent className="pt-4">
                    <div className="grid md:grid-cols-2 gap-4">
                      <div>
                        <h4 className="text-white font-medium mb-2">{item.step_name}</h4>
                        <div className="space-y-1 text-sm text-gray-300">
                          <p><span className="text-gray-400">Proje:</span> {item.project_name}</p>
                          <p><span className="text-gray-400">Parça No:</span> {item.part_number}</p>
                          <p><span className="text-gray-400">Operatör:</span> {item.operator_name}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-lg font-bold text-green-400 mb-2">
                          Bu işlem {formatDuration(item.duration_minutes)} sürmüştür.
                        </div>
                        <div className="space-y-1 text-xs text-gray-400">
                          <p>Başlangıç: {formatDateTime(item.start_time)}</p>
                          <p>Bitiş: {formatDateTime(item.end_time)}</p>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

// Main App Component with Role-Based Interface
const MainApp = () => {
  const { user, logout } = React.useContext(AuthContext);

  // If user is operator, show only the dedicated scanner interface
  if (user?.role === 'operator') {
    return <OperatorScanner />;
  }

  // For managers and admins, show the full interface with navigation
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-slate-800">
      <nav className="bg-black/20 backdrop-blur-lg border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-2">
              <img 
                src="https://customer-assets.emergentagent.com/job_metalops/artifacts/i1dybgg7_Velar%20Makine%20Logo%20SVG.png" 
                alt="Velar Makine Logo" 
                className="h-8 w-8 object-contain"
              />
              <span className="text-xl font-bold text-white">Velar Makine Üretim Takip Sistemi</span>
            </div>
            
            <div className="flex items-center gap-4">
              <Badge className="bg-blue-600/20 text-blue-300 border-blue-600/30">
                {user?.role?.toUpperCase() || 'USER'}
              </Badge>
              <span className="text-gray-300">Merhaba, {user?.username}</span>
              <Button 
                onClick={logout} 
                variant="outline" 
                size="sm"
                className="border-white/20 text-white hover:bg-white/10"
              >
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </Button>
            </div>
          </div>
        </div>
      </nav>
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Tabs defaultValue="scanner" className="space-y-6">
          <TabsList className={`grid w-full ${(user?.role === 'manager' || user?.role === 'admin') ? 'grid-cols-5' : 'grid-cols-4'} bg-white/10 backdrop-blur-lg`}>
            <TabsTrigger value="scanner" className="data-[state=active]:bg-white/20">
              <Scan className="h-4 w-4 mr-2" />
              Scanner
            </TabsTrigger>
            <TabsTrigger value="dashboard" className="data-[state=active]:bg-white/20">
              <BarChart3 className="h-4 w-4 mr-2" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="projects" className="data-[state=active]:bg-white/20">
              <Settings className="h-4 w-4 mr-2" />
              Projeler ve İş Emirleri
            </TabsTrigger>
            <TabsTrigger value="qrcodes" className="data-[state=active]:bg-white/20">
              <QrCode className="h-4 w-4 mr-2" />
              QR Kodlar
            </TabsTrigger>
            {(user?.role === 'manager' || user?.role === 'admin') && (
              <TabsTrigger value="veriler" className="data-[state=active]:bg-white/20">
                <Database className="h-4 w-4 mr-2" />
                Veriler
              </TabsTrigger>
            )}
          </TabsList>
          
          <TabsContent value="scanner">
            <QRScanner />
          </TabsContent>
          
          <TabsContent value="dashboard">
            <Dashboard />
          </TabsContent>
          
          <TabsContent value="projects">
            <Projects />
          </TabsContent>
          
          <TabsContent value="qrcodes">
            <QRCodes />
          </TabsContent>
          
          <TabsContent value="veriler">
            <Veriler />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

// Helper function for status colors
const getStatusColor = (status) => {
  switch (status) {
    case 'pending': return 'bg-gray-500';
    case 'in_progress': return 'bg-blue-500';  
    case 'completed': return 'bg-green-500';
    case 'blocked': return 'bg-red-500';
    default: return 'bg-gray-500';
  }
};

// Helper function for status icons
const getStatusIcon = (status) => {
  switch (status) {
    case 'pending': return <Clock className="h-4 w-4" />;
    case 'in_progress': return <Play className="h-4 w-4" />;
    case 'completed': return <CheckCircle className="h-4 w-4" />;
    case 'blocked': return <Pause className="h-4 w-4" />;
    default: return <Clock className="h-4 w-4" />;
  }
};

// Root App Component with Routes
function App() {
  return (
    <AuthProvider>
      <div className="App">
        <BrowserRouter>
          <Routes>
            <Route path="/" element={
              <AuthContext.Consumer>
                {({ user, loading }) => (
                  loading ? (
                    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-slate-800 flex items-center justify-center">
                      <div className="text-center">
                        <Loader2 className="h-8 w-8 animate-spin text-white mx-auto mb-4" />
                        <p className="text-white">Yükleniyor...</p>
                      </div>
                    </div>
                  ) : user ? <Navigate to="/dashboard" replace /> : <Login />
                )}
              </AuthContext.Consumer>
            } />
            <Route path="/dashboard" element={
              <ProtectedRoute element={<MainApp />} />
            } />
            <Route path="/operator" element={
              <ProtectedRoute element={<OperatorScanner />} requiredRoles={['operator']} />
            } />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </div>
    </AuthProvider>
  );
}

export default App;

