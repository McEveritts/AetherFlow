import { useState } from 'react';
import { useToast } from '@/contexts/ToastContext';
import { ArrowRight, Check, Shield, Server, Box, Globe } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { apiFetch } from '@/lib/fetcher';
import { MotionPresets } from '@/lib/design';

interface OnboardingWizardProps {
    initialSettings: Record<string, unknown>;
    onComplete: () => void;
}

export default function OnboardingWizard({ initialSettings, onComplete }: OnboardingWizardProps) {
    const { addToast } = useToast();
    const [step, setStep] = useState(1);
    const [isSaving, setIsSaving] = useState(false);
    const [baseDomain, setBaseDomain] = useState<string>(
        typeof initialSettings?.baseDomain === 'string' ? initialSettings.baseDomain : ''
    );

    const handleNext = () => setStep(s => Math.min(s + 1, 2));
    const handlePrev = () => setStep(s => Math.max(s - 1, 1));

    const handleFinish = async () => {
        setIsSaving(true);
        try {
            const payload = {
                ...initialSettings,
                baseDomain: baseDomain.trim(),
                setupCompleted: true
            };

            let res = null;
            let retries = 3;
            
            while (retries > 0) {
                try {
                    res = await apiFetch('/api/v1/admin/settings', {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    if (res.ok) break;
                } catch (e) {
                    console.warn(`Setup sync failed, retries left: ${retries - 1}`, e);
                }
                retries--;
                if (retries > 0) await new Promise(r => setTimeout(r, 1000));
            }

            if (res && res.ok) {
                addToast('Welcome to AetherFlow! Nexus is ready.', 'success');
                onComplete();
            } else {
                addToast('Failed to complete setup after multiple attempts.', 'error');
            }
        } catch (_err) {
            addToast('Fatal error during setup completion.', 'error');
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <motion.div 
            initial={{ opacity: 0 }} 
            animate={{ opacity: 1 }} 
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
            className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/80 backdrop-blur-md p-4"
        >
            {/* Ambient Background Glows */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] pointer-events-none">
                <div className="absolute inset-0 bg-indigo-600/20 blur-[120px] rounded-full mix-blend-screen animate-pulse-slow"></div>
                <div className="absolute inset-0 bg-blue-600/10 blur-[100px] translate-x-1/4 translate-y-1/4 rounded-full mix-blend-screen"></div>
            </div>

            <div className="relative w-full max-w-2xl glass-card p-8 overflow-hidden backdrop-blur-3xl shadow-[0_0_50px_rgba(0,0,0,0.5)] border-white/10">
                {/* Progress Bar */}
                <div className="flex items-center gap-2 mb-8">
                    {[1, 2].map((s) => (
                        <div key={s} className={`h-1.5 flex-1 rounded-full transition-all duration-500 ${step >= s ? 'bg-indigo-500 shadow-[0_0_10px_rgba(99,102,241,0.5)]' : 'bg-white/5'}`}></div>
                    ))}
                </div>

                {/* Step Content */}
                <div className="min-h-[320px] relative">
                    <AnimatePresence mode="wait">
                        {step === 1 && (
                            <motion.div 
                                key="step1"
                                variants={MotionPresets.slideUp}
                                initial="hidden" animate="visible" exit="exit"
                                className="space-y-6"
                            >
                                <div className="h-16 w-16 min-w-[4rem] rounded-2xl bg-gradient-to-br from-indigo-500 via-blue-600 to-indigo-800 flex items-center justify-center shadow-[0_0_30px_rgba(99,102,241,0.4)] mb-6">
                                    <span className="font-extrabold text-white text-3xl tracking-tighter mix-blend-screen drop-shadow-md">A</span>
                                </div>
                                <h2 className="text-3xl font-extrabold text-white tracking-tight">Welcome to AetherFlow</h2>
                                <p className="text-slate-400 text-lg leading-relaxed">
                                    Your next-generation homelab operations dashboard. AetherFlow combines powerful remote server management with intelligent local FlowAI automation.
                                </p>

                                <div className="grid grid-cols-2 gap-4 mt-8">
                                    <div className="p-4 rounded-2xl bg-white/5 border border-white/5 flex gap-4 items-start">
                                        <Server className="text-blue-400 shrink-0" />
                                        <div>
                                            <h4 className="text-white font-bold text-sm">Nexus Connected</h4>
                                            <p className="text-xs text-slate-500 mt-1">Go backend service is established and metrics are streaming.</p>
                                        </div>
                                    </div>
                                    <div className="p-4 rounded-2xl bg-white/5 border border-white/5 flex gap-4 items-start">
                                        <Shield className="text-emerald-400 shrink-0" />
                                        <div>
                                            <h4 className="text-white font-bold text-sm">Secure by Default</h4>
                                            <p className="text-xs text-slate-500 mt-1">End-to-end encryption setup is validated.</p>
                                        </div>
                                    </div>
                                </div>

                                <div className="p-4 rounded-2xl bg-white/5 border border-white/10 space-y-2 mt-4">
                                    <label className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                                        <Globe size={14} className="text-indigo-400" /> Server Base Domain (Optional)
                                    </label>
                                    <input
                                        type="text"
                                        value={baseDomain}
                                        onChange={(e) => setBaseDomain(e.target.value)}
                                        placeholder="domain.com (auto-creates jellyfin.domain.com on app install)"
                                        className="w-full bg-slate-900/80 border border-white/10 rounded-xl px-4 py-2.5 text-slate-200 text-sm font-mono focus:outline-none focus:border-indigo-500/50 transition-colors"
                                    />
                                </div>
                            </motion.div>
                        )}

                        {step === 2 && (
                            <motion.div 
                                key="step2"
                                variants={MotionPresets.slideUp}
                                initial="hidden" animate="visible" exit="exit"
                                className="space-y-6 h-full flex flex-col justify-center py-8"
                            >
                                <div className="text-center space-y-4">
                                    <div className="mx-auto w-20 h-20 bg-emerald-500/20 text-emerald-400 rounded-full flex items-center justify-center relative">
                                        <div className="absolute inset-0 bg-emerald-500/10 rounded-full animate-ping"></div>
                                        <Check size={40} />
                                    </div>
                                    <h2 className="text-3xl font-bold text-white tracking-tight">All Set!</h2>
                                    <p className="text-slate-400 max-w-sm mx-auto">
                                        Your environment is fully configured. You can manage AI models and API keys anytime in the Settings page.
                                    </p>
                                </div>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>

                {/* Footer Controls */}
                <div className="flex items-center justify-between mt-10 pt-6 border-t border-white/5">
                    <button
                        onClick={handlePrev}
                        className={`px-6 py-2.5 rounded-xl font-semibold text-sm transition-colors ${step === 1 ? 'opacity-0 pointer-events-none' : 'text-slate-400 hover:text-white hover:bg-white/5'}`}
                    >
                        Back
                    </button>

                    {step < 2 ? (
                        <button
                            onClick={handleNext}
                            className="px-6 py-2.5 bg-indigo-500 hover:bg-indigo-400 text-white rounded-xl font-bold text-sm shadow-[0_0_15px_rgba(99,102,241,0.4)] flex items-center gap-2 transition-all"
                        >
                            Continue <ArrowRight size={16} />
                        </button>
                    ) : (
                        <button
                            onClick={handleFinish}
                            disabled={isSaving}
                            className="px-8 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 disabled:opacity-50 rounded-xl font-bold text-sm shadow-[0_0_15px_rgba(16,185,129,0.4)] flex items-center gap-2 transition-all"
                        >
                            {isSaving ? 'Finishing...' : 'Enter Dashboard'} <Box size={16} />
                        </button>
                    )}
                </div>
            </div>
        </motion.div>
    );
}
