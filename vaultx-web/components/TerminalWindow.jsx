'use client';

import React from 'react';

/**
 * TerminalWindow
 * Matte charcoal (#0B0C10) glass card with razor-thin border-white/10
 * and subtle Deep Violet + Crimson ambient underglow.
 */
export function TerminalWindow({
  className = '',
  children,
}) {
  return (
    <div
      className={`rounded-xl border border-white/10 bg-[#0B0C10]/90 backdrop-blur-xl shadow-[0_0_80px_-20px_rgba(124,58,237,0.22),inset_0_1px_0_rgba(255,255,255,0.06)] ${className}`}
    >
      {children}
    </div>
  );
}

export default TerminalWindow;
