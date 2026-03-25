import { useAuth } from "@workspace/replit-auth-web";
import { useEffect } from "react";
import { Shield, Loader2 } from "lucide-react";
import { motion } from "framer-motion";

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading, login } = useAuth();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      login();
    }
  }, [isLoading, isAuthenticated, login]);

  if (isLoading || !isAuthenticated) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-background relative overflow-hidden">
        <div className="absolute inset-0 z-0 flex items-center justify-center opacity-10">
          <div className="w-96 h-96 bg-primary/20 rounded-full blur-[100px]" />
        </div>
        
        <motion.div 
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="z-10 flex flex-col items-center gap-6"
        >
          <div className="relative">
            <div className="absolute inset-0 bg-primary/20 rounded-full animate-ping" />
            <div className="w-20 h-20 bg-card border border-white/10 rounded-2xl flex items-center justify-center shadow-2xl relative z-10">
              <Shield className="w-10 h-10 text-primary" />
            </div>
            <div className="absolute -bottom-2 -right-2 w-8 h-8 bg-secondary rounded-full flex items-center justify-center border border-background">
              <Loader2 className="w-4 h-4 text-foreground animate-spin" />
            </div>
          </div>
          
          <div className="text-center">
            <h2 className="font-display text-xl font-bold text-foreground">Authenticating</h2>
            <p className="text-muted-foreground text-sm mt-1">Securing your session...</p>
          </div>
        </motion.div>
      </div>
    );
  }

  return <>{children}</>;
}
