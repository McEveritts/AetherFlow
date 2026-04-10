"use client";

import { motion } from 'framer-motion';
import { Button } from '@aetherflow/ui';
import { heroData } from '../content/home';

export function Hero() {
  return (
    <section className="relative pt-20 pb-16">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        className="max-w-4xl"
      >
        <h1 className="text-5xl md:text-7xl font-bold tracking-tight text-white mb-8">
          {heroData.h1}
        </h1>
        <p className="text-xl md:text-2xl text-gray-400 leading-relaxed mb-10 max-w-3xl">
          {heroData.subheadline}
        </p>
        <div className="flex flex-wrap gap-4">
          <a href={heroData.primaryCta.href} target="_blank" rel="noreferrer">
            <Button variant="primary" className="text-lg px-8 py-3 h-auto">
              {heroData.primaryCta.label}
            </Button>
          </a>
        </div>
      </motion.div>
      
      {/* Decorative background glow */}
      <div className="absolute top-0 right-0 -z-10 w-[800px] h-[800px] opacity-20 pointer-events-none">
        <div className="absolute inset-0 bg-blue-600 rounded-full blur-[120px] mix-blend-screen transform translate-x-1/2 -translate-y-1/4" />
      </div>
    </section>
  );
}
