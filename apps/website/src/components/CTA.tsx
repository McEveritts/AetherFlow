"use client";

import { motion } from 'framer-motion';
import { Button } from '@aetherflow/ui';
import { ctaData } from '../content/home';

export function CTA() {
  return (
    <section className="text-center pt-12 pb-24 border-t border-border/50">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        whileInView={{ opacity: 1, scale: 1 }}
        viewport={{ once: true, margin: "-100px" }}
        className="max-w-2xl mx-auto space-y-8"
      >
        <h2 className="text-4xl font-semibold text-white">{ctaData.title}</h2>
        <p className="text-xl text-gray-400">{ctaData.body}</p>
        <div className="flex justify-center">
          <a href={ctaData.button.href} target="_blank" rel="noreferrer">
            <Button variant="primary" className="text-lg px-10 py-4 h-auto">
              {ctaData.button.label}
            </Button>
          </a>
        </div>
      </motion.div>
    </section>
  );
}
