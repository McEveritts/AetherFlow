"use client";

import { motion } from 'framer-motion';
import { aiNativeLoopData } from '../content/home';
import { CheckCircle2 } from 'lucide-react';

export function AINativeLoop() {
  return (
    <section>
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, margin: "-100px" }}
        className="mb-12"
      >
        <h2 className="text-3xl font-semibold text-white mb-4">{aiNativeLoopData.title}</h2>
        <p className="text-xl text-gray-400 max-w-3xl">{aiNativeLoopData.body}</p>
      </motion.div>

      <div className="space-y-6 max-w-3xl">
        {aiNativeLoopData.bullets.map((bullet, idx) => (
          <motion.div
            key={idx}
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ delay: idx * 0.15 }}
            className="flex gap-4 items-start"
          >
            <CheckCircle2 className="w-6 h-6 text-blue-500 mt-1 shrink-0" />
            <div>
              <h3 className="text-lg font-medium text-white mb-2">{bullet.title}</h3>
              <p className="text-gray-400 leading-relaxed text-sm">{bullet.copy}</p>
            </div>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
