import './globals.css';
import { CyberBackdrop } from '../components/CyberBackdrop.jsx';

export const metadata = {
  title: "VaultX | Zero-Knowledge File & Secret Sharing",
  description: "Secure, client-side encrypted zero-knowledge file and secret sharing platform.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="dark">
      <body className="font-sans antialiased bg-[#050508] text-[#FAFAFA] min-h-screen selection:bg-[#7C3AED]/30 selection:text-white">
        <CyberBackdrop />
        {children}
      </body>
    </html>
  );
}
