import { useState } from 'react';
import { useToast } from '@/contexts/ToastContext';
import { Sparkles, ArrowRight, Check, Shield, Server, Box } from 'lucide-react';

interface OnboardingWizardProps {
    initialSettings: any;
    onComplete: () => void;
}

export default function OnboardingWizard({ initialSettings, onComplete }: OnboardingWizardProps) {
    const { addToast } = useToast();
    const [step, setStep] = useState(1);
    const [isSaving, setIsSaving] = useState(false);

    // We only expose a few settings for onboarding to keep it simple
    const [aiModel, setAiModel] = useState(initialSettings?.aiModel || 'gemini-1.5-ultra');

    const handleNext = () => setStep(s => Math.min(s + 1, 3));
    const handlePrev = () => setStep(s => Math.max(s - 1, 1));

    const handleFinish = async () => {
        setIsSaving(true);
        try {
            const payload = {
                ...initialSettings,
                aiModel: aiModel,
                setupCompleted: true
            };

            const res = await fetch('http://localhost:8080/api/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                addToast('Welcome to AetherFlow! Nexus is ready.', 'success');
                onComplete();
            } else {
                addToast('Failed to complete setup.', 'error');
            }
        } catch (err) {
            addToast('Network error during setup completion.', 'error');
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/80 backdrop-blur-md animate-fade-in p-4">
            {/* Ambient Background Glows */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] pointer-events-none">
                <div className="absolute inset-0 bg-indigo-600/20 blur-[120px] rounded-full mix-blend-screen animate-pulse-slow"></div>
                <div className="absolute inset-0 bg-blue-600/10 blur-[100px] translate-x-1/4 translate-y-1/4 rounded-full mix-blend-screen"></div>
            </div>

            <div className="relative w-full max-w-2xl bg-white/[0.02] border border-white/10 rounded-3xl p-8 shadow-2xl overflow-hidden backdrop-blur-2xl">
                {/* Progress Bar */}
                <div className="flex items-center gap-2 mb-8">
                    {[1, 2, 3].map((s) => (
                        <div key={s} className={`h-1.5 flex-1 rounded-full transition-all duration-500 ${step >= s ? 'bg-indigo-500 shadow-[0_0_10px_rgba(99,102,241,0.5)]' : 'bg-white/5'}`}></div>
                    ))}
                </div>

                {/* Step Content */}
                <div className="min-h-[300px] relative">
                    {step === 1 && (
                        <div className="space-y-6 animate-slide-up">
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
                        </div>
                    )}

                    {step === 2 && (
                        <div className="space-y-6 animate-slide-up">
                            <div className="flex items-center gap-3 mb-6">
                                <div className="p-3 bg-indigo-500/20 text-indigo-400 rounded-xl">
                                    <Sparkles size={24} />
                                </div>
                                <h2 className="text-2xl font-bold text-white tracking-tight">Configure FlowAI</h2>
                            </div>

                            <p className="text-slate-400 text-sm">
                                AetherFlow uses a local conversational assistant to help you debug systems, write container configurations, and analyze logs.
                            </p>

                            <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6 mt-6">
                                <label className="block text-sm font-semibold text-slate-300 mb-3">Primary Language Model</label>
                                <div className="space-y-3">
                                    {['gemini-1.5-ultra', 'gemini-1.5-pro', 'gemini-1.0-pro'].map((m) => (
                                        <button
                                            key={m}
                                            onClick={() => setAiModel(m)}
                                            className={`w-full flex items-center justify-between p-4 rounded-xl border transition-all ${aiModel === m ? 'bg-indigo-500/10 border-indigo-500/50 text-indigo-300' : 'bg-white/5 border-white/5 text-slate-400 hover:bg-white/10'}`}
                                        >
                                            <span className="font-medium tracking-wide">{m}</span>
                                            {aiModel === m && <Check size={18} />}
                                        </button>
                                    ))}
                                </div>
                                <p className="text-xs text-slate-500 mt-4">This can be changed later in the Settings tab.</p>
                            </div>
                        </div>
                    )}

                    {step === 3 && (
                        <div className="space-y-6 animate-slide-up h-full flex flex-col justify-center py-8">
                            <div className="text-center space-y-4">
                                <div className="mx-auto w-20 h-20 bg-emerald-500/20 text-emerald-400 rounded-full flex items-center justify-center relative">
                                    <div className="absolute inset-0 bg-emerald-500/10 rounded-full animate-ping"></div>
                                    <Check size={40} />
                                </div>
                                <h2 className="text-3xl font-bold text-white tracking-tight">All Set!</h2>
                                <p className="text-slate-400 max-w-sm mx-auto">
                                    Your environment is fully configured. You are ready to manage your infrastructure through the Nexus ring.
                                </p>
                            </div>
                        </div>
                    )}
                </div>

                {/* Footer Controls */}
                <div className="flex items-center justify-between mt-10 pt-6 border-t border-white/5">
                    <button
                        onClick={handlePrev}
                        className={`px-6 py-2.5 rounded-xl font-semibold text-sm transition-colors ${step === 1 ? 'opacity-0 pointer-events-none' : 'text-slate-400 hover:text-white hover:bg-white/5'}`}
                    >
                        Back
                    </button>

                    {step < 3 ? (
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
        </div>
    );
}
