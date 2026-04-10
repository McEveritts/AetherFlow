"use client";

import { motion } from 'framer-motion';
import { Card, CardHeader, CardTitle, CardContent } from '@aetherflow/ui';
import { directives } from '../content/home';

export function CoreDirectives() {
  return (
    <section>
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, margin: "-100px" }}
        className="mb-12"
      >
        <h2 className="text-3xl font-semibold text-white mb-4">{directives.title}</h2>
        <p className="text-xl text-gray-400 max-w-3xl">{directives.body}</p>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {directives.cards.map((card, idx) => (
          <motion.div
            key={idx}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-50px" }}
            transition={{ delay: idx * 0.1 }}
          >
            <Card className="h-full bg-surface/50 backdrop-blur-sm border-border/50 hover:border-border transition-colors">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white">{card.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-400 leading-relaxed text-sm">
                  {card.copy}
                </p>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
