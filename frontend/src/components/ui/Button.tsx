import { cn } from "@/lib/utils";
import React from "react";

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "primary" | "ghost" | "danger";
  size?: "sm" | "md" | "lg" | "icon";
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "md", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center rounded-xl font-medium obs-gpu-120hz-interactive focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 focus-visible:ring-offset-2 focus-visible:ring-offset-black disabled:pointer-events-none disabled:opacity-50 cursor-pointer select-none",
          // Sizing with touch target compliance
          size === "sm" && "min-h-[36px] px-3 text-xs",
          size === "md" && "min-h-[44px] h-10 px-4 py-2 text-sm obs-touch-target-standard",
          size === "lg" && "min-h-[48px] h-12 px-6 text-base obs-touch-target-standard",
          size === "icon" && "min-h-[44px] min-w-[44px] h-10 w-10 p-0 obs-touch-target-standard",
          // Obsidian V2 Variants
          variant === "default" && "glass-button",
          variant === "primary" && "glass-button-primary",
          variant === "ghost" && "hover:bg-white/10 text-slate-300 hover:text-white rounded-xl transition-colors",
          variant === "danger" && "bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 border border-rose-500/30 rounded-xl shadow-[0_4px_16px_rgba(244,63,94,0.2)]",
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";
