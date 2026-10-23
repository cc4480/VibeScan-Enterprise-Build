import { HeroSection, ProblemSection, HowItWorksSection, AiBuilderSection } from "./landing-sections";
import { McpSection, OwaspSection } from "./landing-tools";
import { PricingSection } from "./landing-pricing";
import { useSeo } from "@/lib/seo";

export default function LandingPage() {
  // No title or description: the server already renders the right ones for "/"
  // in index.html, and a second copy here would be one to keep in step. This is
  // for the canonical, which client-side routing otherwise leaves pointing at
  // whichever page the visitor entered on.
  useSeo({});

  return (
    <div className="flex flex-col gap-24 lg:gap-32">
      <HeroSection />
      <ProblemSection />
      <HowItWorksSection />
      <AiBuilderSection />
      <McpSection />
      <OwaspSection />
      <PricingSection />
    </div>
  );
}
