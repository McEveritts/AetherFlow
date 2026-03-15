import { cn } from "@/lib/utils";
import React from "react";

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "primary" | "ghost";
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center rounded-xl text-sm font-medium transition-colors focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50",
          "h-10 px-4 py-2",
          variant === "default" && "glass-button",
          variant === "primary" && "glass-button-primary",
          variant === "ghost" && "hover:bg-white/5 text-slate-300 hover:text-white",
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";
