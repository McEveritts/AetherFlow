import { loadCatalogData } from '@/lib/catalog';
import { inspectAvailableMedia } from '@/lib/media';
import { MotionProvider } from '@/components/MotionProvider';
import { Navbar } from '@/components/Navbar';
import { HeroSection } from '@/components/HeroSection';
import { StatsBand } from '@/components/StatsBand';
import { FeatureGrid } from '@/components/FeatureGrid';
import { ScreenshotGallery } from '@/components/ScreenshotGallery';
import { ArchitectureSection } from '@/components/ArchitectureSection';
import { PeerClusteringSection } from '@/components/PeerClusteringSection';
import { CatalogShowcase } from '@/components/CatalogShowcase';
import { InstallSection } from '@/components/InstallSection';
import { WhatsNewSection } from '@/components/WhatsNewSection';
import { Footer } from '@/components/Footer';

export default function Home() {
  const catalog = loadCatalogData();
  const media = inspectAvailableMedia();

  return (
    <MotionProvider>
      <div className="min-h-screen">
        <Navbar />
        <main id="main-content">
          <HeroSection
            heroScreenshots={{
              dark: media.screenshots.dark.overview ?? null,
              light: media.screenshots.light.overview ?? null,
            }}
          />
          <StatsBand />
          <FeatureGrid featureIcons={media.featureIcons} />
          <ScreenshotGallery screenshots={media.screenshots} />
          <ArchitectureSection
            architectureSvgSrc={media.diagrams.architecture}
          />
          <PeerClusteringSection
            peerClusteringSvgSrc={media.diagrams.peerClustering}
          />
          <CatalogShowcase
            apps={catalog.apps}
            categories={catalog.categories}
            totalCount={catalog.totalCount}
          />
          <InstallSection />
          <WhatsNewSection />
        </main>
        <Footer />
      </div>
    </MotionProvider>
  );
}
