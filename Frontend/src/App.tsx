import React, { useState } from 'react';
import './App.css';

function App() {
  const [view, setView] = useState<'login' | 'register' | 'texto'>('login');
  return (
    <div className="App" style={{ textAlign: 'center', fontFamily: 'Arial', marginTop: '50px' }}>
      <nav style={{ padding: '10px', background: '#ccc', marginBottom: '20px', borderRadius: '8px', display: 'inline-block' }}>
        <button onClick={() => setView('login')} style={{ marginRight: '10px', padding: '10px', cursor: 'pointer' }}>Login</button>
        <button onClick={() => setView('register')} style={{ marginRight: '10px', padding: '10px', cursor: 'pointer' }}>Registro</button>
        <button onClick={() => setView('texto')} style={{ padding: '10px', cursor: 'pointer' }}>Texto (Hash)</button>
      </nav>
      {view === 'login' && <Login />}
      {view === 'register' && <Registro />}
      {view === 'texto' && <Texto />}
    </div>
  );
}

function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mensaje, setMensaje] = useState();

  const str2ab = (str: string) => {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  };

  const login = async () => {
    try {
      // Peticion para la llave publica
      const pkRes = await fetch("http://localhost:5500/public-key");
      const pkData = await pkRes.json();

      const pemHeader = "-----BEGIN PUBLIC KEY-----";
      const pemFooter = "-----END PUBLIC KEY-----";
      const pemContents = pkData.publicKey.substring(
        pkData.publicKey.indexOf(pemHeader) + pemHeader.length,
        pkData.publicKey.indexOf(pemFooter)
      ).replace(/\s/g, '');
      const binaryDerString = window.atob(pemContents);
      const binaryDer = str2ab(binaryDerString);

      const rsaPubKey = await window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );

      // Generar llave AES-GCM
      const aesKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      const aesKeyRaw = await window.crypto.subtle.exportKey("raw", aesKey);

      // Encriptar llave AES con la llave publica RSA
      const encryptedAesKeyBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        rsaPubKey,
        aesKeyRaw
      );

      // Encriptar credenciales AES
      const credentials = JSON.stringify({ username, password });
      const encodedCredentials = new TextEncoder().encode(credentials);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encryptedCredentialsBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        encodedCredentials
      );

      const payloadBuffer = new Uint8Array(iv.length + encryptedCredentialsBuffer.byteLength);
      payloadBuffer.set(iv, 0);
      payloadBuffer.set(new Uint8Array(encryptedCredentialsBuffer), iv.length);

      const bufferToBase64 = (buffer: ArrayBuffer) => {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
      };

      // Mandar los datos al backend
      const res = await fetch("http://localhost:5500/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          encryptedCredentials: bufferToBase64(payloadBuffer.buffer),
          encryptedKey: bufferToBase64(encryptedAesKeyBuffer)
        })
      });

      const data = await res.json();
      if (data.mensaje) {
        setMensaje(data.mensaje);
      } else {
        setMensaje(data.mensaje);
      }
    } catch (e: any) {
      console.error(e);
      setMensaje(e.mensaje);
    }
  };

  return (
    <div className="container" style={{ maxWidth: '300px', margin: '0 auto', textAlign: 'left', background: '#f5f5f5', padding: '20px', borderRadius: '10px' }}>
      <h2 style={{ textAlign: 'center', color: '#123c6b' }}>Login</h2>
      <label>Correo</label>
      <input style={{ display: 'block', width: '100%', marginBottom: '15px', padding: '10px', boxSizing: 'border-box' }} type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="correo" />
      <label>Contraseña</label>
      <input style={{ display: 'block', width: '100%', marginBottom: '15px', padding: '10px', boxSizing: 'border-box' }} type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" />
      <button style={{ width: '100%', padding: '12px', background: '#0b3c74', color: 'white', border: 'none', borderRadius: '8px', cursor: 'pointer' }} onClick={login}>Iniciar Sesión</button>
      {mensaje &&
        <div className='container' style={{ maxWidth: '300px', maxHeight: '50px', background: '#d9e29c' }}>
          <p>{mensaje}</p>
        </div>
      }
    </div>
  );
}

function Registro() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mensaje, setMensaje] = useState("");

  const registrar = async () => {
    try {
      const res = await fetch("http://localhost:5500/registro", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (data.mensaje) {
        setMensaje(data.mensaje);
      } else {
        setMensaje(data.mensaje);
      }
    } catch (e) {
      alert("No hay conexion con el backend");
    }
  };

  return (
    <div className="container" style={{ maxWidth: '300px', margin: '0 auto', textAlign: 'left', background: '#f5f5f5', padding: '20px', borderRadius: '10px' }}>
      <h2 style={{ textAlign: 'center', color: '#123c6b' }}>Registro</h2>
      <label>Correo</label>
      <input style={{ display: 'block', width: '100%', marginBottom: '15px', padding: '10px', boxSizing: 'border-box' }} type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="correo" />
      <label>Contraseña</label>
      <input style={{ display: 'block', width: '100%', marginBottom: '15px', padding: '10px', boxSizing: 'border-box' }} type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" />
      <button style={{ width: '100%', padding: '12px', background: '#0b3c74', color: 'white', border: 'none', borderRadius: '8px', cursor: 'pointer' }} onClick={registrar}>Registrarse</button>
      {mensaje &&
        <div className='container' style={{ maxWidth: '300px', maxHeight: '50px', background: '#d9e29c' }}>
          <p>{mensaje}</p>
        </div>
      }
    </div>
  );
}

function Texto() {
  const [texto, setTexto] = useState("");
  const [mensaje, setMensaje] = useState("");

  const guardarTexto = async () => {
    try {
      const res = await fetch("http://localhost:5500/texto", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ texto })
      });
      const data = await res.json();
      if (data.hash) {
        setMensaje(data.mensaje + data.hash);
      } else {
        setMensaje("ERROR: " + data.error);
      }
    } catch (e) {
      setMensaje("No hay conexion con el backend");
    }
  };

  return (
    <div className="container" style={{ maxWidth: '300px', margin: '0 auto', textAlign: 'left', background: '#f5f5f5', padding: '20px', borderRadius: '10px' }}>
      <h2 style={{ textAlign: 'center', color: '#123c6b' }}>Guardar texto en hash</h2>
      <label>Texto:</label>
      <input style={{ display: 'block', width: '100%', marginBottom: '15px', padding: '10px', boxSizing: 'border-box' }} type="text" value={texto} onChange={(e) => setTexto(e.target.value)} placeholder="Escribe el texto..." />
      <button style={{ width: '100%', padding: '12px', background: '#0b3c74', color: 'white', border: 'none', borderRadius: '8px', cursor: 'pointer' }} onClick={guardarTexto}>Generar Hash</button>
      {mensaje &&
        <div className='container' style={{ maxWidth: '300px', maxHeight: '50px', background: '#d9e29c' }}>
          <p>{mensaje}</p>
        </div>
      }
    </div>
  );
}

export default App;
