"use client";

import { motion } from 'framer-motion';
import { architectureData } from '../content/home';

export function Architecture() {
  return (
    <section className="relative">
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, margin: "-100px" }}
        className="mb-12"
      >
        <h2 className="text-3xl font-semibold text-white mb-4">{architectureData.title}</h2>
        <p className="text-xl text-gray-400 max-w-3xl">{architectureData.body}</p>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {architectureData.columns.map((col, idx) => (
          <motion.div
            key={idx}
            initial={{ opacity: 0, x: idx === 0 ? -20 : 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ delay: 0.2 }}
            className="p-8 rounded-2xl bg-gradient-to-b from-surface/80 to-surface/40 border border-border/50 relative overflow-hidden"
          >
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500/0 via-blue-500/50 to-blue-500/0 opacity-50" />
            <h3 className="text-xl font-medium text-white mb-4">{col.title}</h3>
            <p className="text-gray-400 leading-relaxed font-mono text-sm opacity-90">
              {col.copy}
            </p>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
