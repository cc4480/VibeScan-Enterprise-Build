import { useEffect, useRef } from "react";
import { Link } from "wouter";
import { motion, useReducedMotion } from "framer-motion";
import { ArrowRight, Activity } from "lucide-react";

/** The hero video above the headline: the SecScan universe animation, an
 *  848x960 loop of 10 seconds (~2.2 MB), video track only. It autoplays muted and inline,
 *  which is what browsers allow without a click. The still shield image is the
 *  poster, so it shows while the video loads, when autoplay is refused, and
 *  for anyone with prefers-reduced-motion, who never gets the video started. */
function HeroVideo({ videoRef }: { videoRef: React.RefObject<HTMLVideoElement | null> }) {
  const reduce = useReducedMotion();
  const base = import.meta.env.BASE_URL;

  // React sets `muted` as a property but never writes the attribute, and the
  // browser's autoplay check reads the attribute, so autoplay alone is refused.
  // defaultMuted writes it; play() then starts the video. Browsers also pause
  // muted video while its tab is in the background, so play() runs again when
  // the tab becomes visible. A refusal just leaves the poster showing.
  useEffect(() => {
    const video = videoRef.current;
    if (!video || reduce) return;
    video.defaultMuted = true;
    video.muted = true;
    const start = () => {
      if (document.visibilityState === "visible") void video.play().catch(() => {});
    };
    start();
    document.addEventListener("visibilitychange", start);
    // There are no controls, so any pause while the tab is showing came from
    // the browser, not the visitor. Start it again.
    video.addEventListener("pause", start);
    return () => {
      document.removeEventListener("visibilitychange", start);
      video.removeEventListener("pause", start);
    };
  }, [reduce, videoRef]);

  return (
    <motion.div
      className="relative mb-8 aspect-[848/960] w-60 overflow-hidden rounded-3xl border border-primary/30 shadow-[0_0_40px_rgba(20,184,120,0.25)] sm:w-72"
      initial={reduce ? false : { opacity: 0, scale: 0.92, y: 10 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ duration: 0.8, ease: [0.2, 0.8, 0.2, 1] }}
    >
      <video
        ref={videoRef}
        className="h-full w-full object-cover"
        src={`${base}videos/secscan-universe-v2.mp4`}
        poster={`${base}images/hero-shield.webp`}
        width={848}
        height={960}
        autoPlay={!reduce}
        loop
        muted
        playsInline
        preload={reduce ? "none" : "auto"}
        aria-hidden="true"
        tabIndex={-1}
      />
    </motion.div>
  );
}

/** The page background: the hero video, playing again behind the whole page. The hero video is the only one that is decoded
 *  and downloaded; every frame it shows is also drawn (about 30 a second, at half its size) into a canvas that covers the
 *  viewport and is only lightly softened, so the same animation plays big behind the page, frame for frame in step with the
 *  one in the hero, and cannot drift from it. It draws nothing for visitors who ask for reduced motion, while the tab is
 *  hidden or the video is paused, or until the video has a frame; the static palette gradient from the layout shows then. */
function VideoAmbientBackdrop({ videoRef }: { videoRef: React.RefObject<HTMLVideoElement | null> }) {
  const reduce = useReducedMotion();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const video = videoRef.current;
    if (!canvas || !video || reduce) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let raf = 0;
    let last = 0;
    const draw = (now: number) => {
      raf = requestAnimationFrame(draw);
      // About 30 frames a second, so the background plays smoothly with the video and does not step.
      if (now - last < 33 || document.visibilityState !== "visible") return;
      last = now;
      if (video.readyState < 2 || video.paused) return;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      canvas.style.opacity = "0.7";
    };
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [reduce, videoRef]);

  if (reduce) return null;
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-[-1] overflow-hidden"
      style={{ maskImage: "radial-gradient(95% 80% at 50% 34%, black 35%, rgba(0,0,0,0.35) 70%, transparent 100%)", WebkitMaskImage: "radial-gradient(95% 80% at 50% 34%, black 35%, rgba(0,0,0,0.35) 70%, transparent 100%)" }}
    >
      <canvas
        ref={canvasRef}
        width={424}
        height={480}
        className="h-full w-full object-cover transition-opacity duration-1000"
        style={{ opacity: 0, filter: "blur(5px) saturate(1.3) contrast(1.1)", transform: "scale(1.06)", mixBlendMode: "screen" }}
      />
    </div>
  );
}

/** The hero: headline, subhead and the two calls to action. */
export function HeroSection() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring" as const, stiffness: 300, damping: 24 } }
  };

  return (
    <section className="relative pt-12 pb-20 lg:pt-24 lg:pb-32 overflow-hidden">
      <VideoAmbientBackdrop videoRef={videoRef} />
      <div className="absolute inset-0 z-0">
        {/* Decorative, so alt="" (screen readers skip it). WebP at 28 KB —
            the PNG it replaced was 991 KB and the largest thing on the page. */}
        <img
          src={`${import.meta.env.BASE_URL}images/hero-bg.webp`}
          alt=""
          aria-hidden="true"
          width={1408}
          height={768}
          fetchPriority="high"
          decoding="async"
          className="w-full h-full object-cover opacity-50 mix-blend-screen"
        />
        <div className="absolute inset-0 bg-gradient-to-b from-background/0 via-background/60 to-background" />
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="show"
          className="max-w-3xl mx-auto text-center flex flex-col items-center"
        >
          <HeroVideo videoRef={videoRef} />

          <motion.div variants={itemVariants} className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium mb-8">
            <Activity className="w-4 h-4" />
            <span>AI Analysis Engine v1.0</span>
          </motion.div>

          <motion.h1 variants={itemVariants} className="text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-6">
            Any website. <br />
            <span className="text-gradient-primary">Is it safe?</span>
          </motion.h1>

          <motion.p variants={itemVariants} className="text-lg md:text-xl text-muted-foreground mb-10 max-w-2xl">
            Paste the URL of an app you own or are authorised to test — yours or a client's — and get a plain-English security report, usually in under a minute. No installs, no agents.
          </motion.p>

          <motion.div variants={itemVariants} className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto">
            <Link
              href="/scan"
              className="w-full sm:w-auto px-8 py-4 bg-primary text-primary-foreground text-lg font-bold rounded-xl shadow-[0_0_30px_rgba(20,184,120,0.25)] hover:shadow-[0_0_40px_rgba(20,184,120,0.4)] hover:-translate-y-1 transition-all duration-300 flex items-center justify-center gap-2"
            >
              Scan Your App <ArrowRight className="w-5 h-5" />
            </Link>
            <a
              href="#pricing"
              className="w-full sm:w-auto px-8 py-4 bg-secondary text-foreground text-lg font-semibold rounded-xl border border-white/5 hover:bg-secondary/80 transition-all duration-300 text-center"
            >
              View Pricing
            </a>
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}
