import { Hero } from '../components/Hero';
import { CoreDirectives } from '../components/CoreDirectives';
import { Architecture } from '../components/Architecture';
import { AINativeLoop } from '../components/AINativeLoop';
import { StatusMomentum } from '../components/StatusMomentum';
import { CTA } from '../components/CTA';

export default function Home() {
  return (
    <main className="min-h-screen bg-[#0f1115] text-[#ececf1] selection:bg-blue-500/30">
      <div className="mx-auto max-w-6xl px-6 py-24 space-y-32">
        <Hero />
        <CoreDirectives />
        <Architecture />
        <AINativeLoop />
        <StatusMomentum />
        <CTA />
      </div>
    </main>
  );
}
