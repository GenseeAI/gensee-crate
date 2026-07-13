import React from 'react';
import ReactDOM from 'react-dom/client';
// Ant Design v5 CSS-in-JS reset — must come before any component renders.
import 'antd/dist/reset.css';
import App from './App';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
