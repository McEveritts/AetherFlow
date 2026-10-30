import React from 'react';
import { render, screen } from '@testing-library/react';
import FlowAiMarkdown from './FlowAiMarkdown';

const SAMPLE_FLOWAI_OUTPUT = `To give you an accurate analysis of your Next.js + Go Nexus environment, I don't currently have live telemetry streaming into this session. However, you can either **paste the output of your metrics** here, or let me know if you want me to trigger a diagnostic data-gathering workflow.

If you'd like to pull the raw data quickly yourself, run these safe, read-only commands and paste the output:

\`\`\`bash
# Check CPU & Memory per process (Top 10)
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 11

# Check overall Memory and Swap
free -m

# Check Disk Space and Inodes
df -h && df -i

# Check I/O Wait and Load Average
uptime && iostat -xz 1 2
\`\`\`

---

### 🔍 Common Bottlenecks in a Next.js + Go Nexus Stack
While I wait for your metrics, here is what I specifically look for in this architecture so you know what we are guarding against:

#### 1. CPU Utilization
* **Next.js SSR / ISR Spikes:** If your Node.js process is pinning a single core at 100%, it usually points to synchronous rendering bottlenecks in Server Components or heavy JSON serialization during Server-Side Rendering (SSR).
* **Go Nexus Concurrency:** Go handles CPU scaling well across cores, but high *System CPU* (\`sy\`) combined with high context switching often indicates unthrottled goroutine spawning or spin-locks in your media pipelines.

#### 2. Memory (RAM & Swap)
* **Node.js V8 Heap Limits:** Next.js image optimization (\`sharp\`) or un-evicted in-memory caches can rapidly consume RAM, triggering V8 Garbage Collection loops (which manifests as high CPU + high latency) or Out-Of-Memory (OOM) kills.
* **Go GC Pressure:** If the Go Nexus service shows a sawtooth memory pattern with high peak allocations, we may need to tune \`GOGC\` or set a hard soft-limit via \`GOMEMLIMIT\` to prevent it from starving the Next.js service.
* **Swap Activity:** Any active swap I/O (\`si\`/\`so\` in \`vmstat\`) will severely degrade Go's scheduler latency and Next.js response times.

#### 3. Disk Space & I/O Wait (\`%iowait\`)
* **Next.js Data Cache (\`/.next/cache\`):** Unbounded ISR (Incremental Static Regeneration) or image caches can silently consume 100% of your **Inodes** long before you actually run out of gigabytes.
* **Media Pipeline Scratch Space:** If your Go Nexus environment processes media locally, high disk \`%iowait\` will block goroutines waiting on \`os.File\` reads/writes, causing cascading latency in your APIs.
* **Unrotated Logs:** Verbose JSON logging from both Go and Next.js can saturate disk I/O throughput if not properly buffered or rotated.

---

### ⚡ Next Steps
1. **Paste your current metrics** (from \`top\`, \`htop\`, Prometheus, or the commands above), and I will pinpoint the exact bottlenecks.
2. **Or, tell me what symptoms you are seeing** (e.g., *high API latency, slow page loads, disk full warnings*), and I will draft a safe, targeted remediation workflow directly to your **Approval Inbox** (such as clearing stale \`.next\` caches, tuning \`GOMEMLIMIT\`, or rotating logs).`;

describe('FlowAiMarkdown', () => {
    it('renders structured headings, code blocks, lists, inline code, and emphasis without raw markdown markers', () => {
        const { container } = render(<FlowAiMarkdown content={SAMPLE_FLOWAI_OUTPUT} />);

        // Headings
        expect(screen.getByRole('heading', { level: 3, name: /Common Bottlenecks in a Next\.js \+ Go Nexus Stack/i })).toBeInTheDocument();
        expect(screen.getByRole('heading', { level: 3, name: /Next Steps/i })).toBeInTheDocument();
        expect(screen.getByRole('heading', { level: 4, name: /1\. CPU Utilization/i })).toBeInTheDocument();
        expect(screen.getByRole('heading', { level: 4, name: /3\. Disk Space & I\/O Wait/i })).toBeInTheDocument();

        // Fenced code block with language badge and Copy button
        expect(screen.getByText('bash')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /copy/i })).toBeInTheDocument();
        expect(container.querySelector('pre code')?.textContent).toContain('ps -eo pid,ppid,cmd,%mem,%cpu');

        // Horizontal rules
        expect(container.querySelectorAll('hr').length).toBe(2);

        // Unordered and ordered lists
        expect(container.querySelectorAll('ul').length).toBe(3);
        expect(container.querySelectorAll('ol').length).toBe(1);

        // Bold & nested inline code inside bold (**Next.js Data Cache (`/.next/cache`):**)
        const strongElements = Array.from(container.querySelectorAll('strong')).map((el) => el.textContent);
        expect(strongElements).toContain('paste the output of your metrics');
        expect(strongElements).toContain('Next.js Data Cache (/.next/cache):');
        expect(strongElements).toContain('Approval Inbox');

        // Inline code elements
        const inlineCodes = Array.from(container.querySelectorAll(':not(pre) > code')).map((el) => el.textContent);
        expect(inlineCodes).toContain('sy');
        expect(inlineCodes).toContain('/.next/cache');
        expect(inlineCodes).toContain('GOMEMLIMIT');

        // Raw markdown delimiters should not appear in rendered text
        expect(container.textContent).not.toContain('```bash');
        expect(container.textContent).not.toContain('### ');
        expect(container.textContent).not.toContain('#### ');
        expect(container.textContent).not.toContain('**paste');
    });

    it('renders release notes markdown with BOM stripping, bold links, and bare URLs cleanly', () => {
        const releaseNotes = `\uFEFF# AetherFlow v3.2.1 Release Notes — 69-App Bare-Metal Catalog\n\n**AetherFlow v3.2.1** compares against [**AetherFlow v3.2.01**](https://github.com/McEveritts/AetherFlow/releases/tag/v3.2.01).\n\n---\n\n## Highlights Since \`v3.2.01\`\n\n**Full Changelog**: https://github.com/McEveritts/AetherFlow/compare/v3.2.01...v3.2.1`;
        const { container } = render(<FlowAiMarkdown content={releaseNotes} />);

        expect(screen.getByRole('heading', { level: 1, name: /AetherFlow v3\.2\.1 Release Notes — 69-App Bare-Metal Catalog/i })).toBeInTheDocument();
        expect(screen.getByRole('heading', { level: 2, name: /Highlights Since v3\.2\.01/i })).toBeInTheDocument();

        const links = Array.from(container.querySelectorAll('a'));
        expect(links.length).toBe(2);
        expect(links[0]).toHaveAttribute('href', 'https://github.com/McEveritts/AetherFlow/releases/tag/v3.2.01');
        expect(links[0].textContent).toBe('AetherFlow v3.2.01');
        expect(links[1]).toHaveAttribute('href', 'https://github.com/McEveritts/AetherFlow/compare/v3.2.01...v3.2.1');
        expect(container.textContent).not.toContain('# AetherFlow');
        expect(container.textContent).not.toContain('**AetherFlow');
    });
});
