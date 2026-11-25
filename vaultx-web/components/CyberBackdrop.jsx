'use client';

import React from 'react';

/**
 * CyberBackdrop
 * Pitch-black (#050508) canvas with a top Deep Violet (#5B21B6/20) + Crimson (#991B1B/15)
 * horizon glow, radially spinning ambient aura, and subtle bottom perspective grid.
 */
export function CyberBackdrop() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-[#050508] select-none"
    >
      {/* Top ambient horizon glow: Deep Violet + Crimson blending into #050508 */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(91,33,182,0.20),rgba(153,27,27,0.15),#050508_70%)]" />

      {/* Radially spinning Deep Violet & Crimson ambient conic aura */}
      <div className="spin-radial-glow absolute left-1/2 top-[38%] h-[1050px] w-[1050px] rounded-full blur-3xl opacity-75" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_38%,transparent_15%,#050508_74%)]" />

      {/* Subtle 3D Perspective Grid along bottom edge */}
      <div className="perspective-stage absolute inset-x-0 bottom-0 h-[220px]">
        <div className="perspective-grid" />
      </div>
    </div>
  );
}

export default CyberBackdrop;
