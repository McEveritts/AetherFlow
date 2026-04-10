"use client";

import { motion } from 'framer-motion';
import { statusMomentumData } from '../content/home';

export function StatusMomentum() {
  return (
    <section>
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, margin: "-100px" }}
        className="mb-12"
      >
        <h2 className="text-3xl font-semibold text-white mb-4">{statusMomentumData.title}</h2>
        <p className="text-xl text-gray-400 max-w-3xl">{statusMomentumData.body}</p>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {statusMomentumData.bullets.map((bullet, idx) => (
          <motion.div
            key={idx}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ delay: idx * 0.1 }}
            className="p-6 rounded-xl bg-surface/30 border border-white/5"
          >
            <h3 className="text-md font-medium text-white mb-3 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-blue-500" />
              {bullet.title}
            </h3>
            <p className="text-gray-400 leading-relaxed text-sm">
              {bullet.copy}
            </p>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
