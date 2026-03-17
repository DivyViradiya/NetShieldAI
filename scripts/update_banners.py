import os
import re
import glob

def process_desktop():
    scanner_dir = r"d:\NetShield\NetShieldAI\templates\scanners"
    desktop_files = glob.glob(os.path.join(scanner_dir, "*.html"))
    
    for fpath in desktop_files:
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()

        # Find the inner HTML of scanner-title-area wrapper
        # We know it starts somewhere after dashboard-wrapper and ends at scan-overview-grid
        start_marker = '<div class="dashboard-wrapper">'
        end_marker = '<div class="scan-overview-grid">'
        
        if start_marker in content and end_marker in content:
            start_idx = content.find(start_marker) + len(start_marker)
            end_idx = content.find(end_marker)
            
            chunk = content[start_idx:end_idx]
            
            # Extract words and subtitle from the chunk
            match = re.search(r'<h1 class="text-gradient"[^>]*>([^<]+)<span[^>]*>([^<]+)</span></h1>\s*<p[^>]*>\s*<span[^>]*></span>\s*([^<]+)\s*</p>', chunk, re.IGNORECASE)
            if match:
                word1 = match.group(1).strip()
                word2 = match.group(2).strip()
                subtitle = match.group(3).strip()

                new_banner = f"""\n    <!-- Top Bento Banner Block -->
    <div class="control-card" style="display: flex; flex-direction: row; justify-content: space-between; align-items: center; padding: 2rem 2.5rem; border-radius: 20px;">
      <div class="scanner-title-area" style="margin: 0;">
        <h1 class="text-gradient" style="margin-bottom: 0.5rem; font-size: 2.25rem; letter-spacing: -0.02em;">{word1} <span style="background: linear-gradient(135deg, var(--neo-blue), var(--neo-cyan)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">{word2}</span></h1>
        <p style="color: var(--neo-text-muted); font-size: 0.85rem; font-weight: 500; font-family: var(--font-mono); margin: 0; display: flex; align-items: center; gap: 16px; opacity: 0.8;">
          <span style="height: 1px; width: 32px; background: linear-gradient(90deg, var(--neo-blue), transparent);"></span>
          {subtitle}
        </p>
      </div>
      
      <div class="flex gap-3">
        <a href="{{{{ url_for('tools_hub') }}}}" class="btn-dash" style="background: rgba(255,255,255,0.05); height: 42px; border-radius: 8px;">
          <span class="material-symbols-outlined" style="font-size: 1.2rem;">home</span>
          <span>Security Hub</span>
        </a>
      </div>
    </div>\n\n    """
                new_content = content[:start_idx] + new_banner + content[end_idx:]
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(new_content)
                print(f"Updated Desktop: {os.path.basename(fpath)}")
            else:
                print(f"Regex failed for Desktop: {os.path.basename(fpath)}")

def process_mobile():
    mobile_dir = r"d:\NetShield\NetShieldAI\templates\mobile_scanners"
    mobile_files = glob.glob(os.path.join(mobile_dir, "*.html"))
    for fpath in mobile_files:
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()

        start_marker = '<div class="top-app-bar">'
        end_marker = '<div class="mobile-wrapper">'
        if start_marker in content and end_marker in content:
            start_idx = content.find(start_marker)
            end_idx = content.find(end_marker)
            chunk = content[start_idx:end_idx]

            match = re.search(r'<div class="title text-gradient">\s*(.*?)\s*<span[^>]*>(.*?)</span>\s*</div>\s*<div class="info-line">(.*?)</div>', chunk, re.IGNORECASE | re.DOTALL)
            if match:
                word1 = match.group(1).strip()
                word2 = match.group(2).strip()
                subtitle = match.group(3).strip()

                new_banner = f"""<div class="control-card" style="display: flex; flex-direction: row; justify-content: space-between; align-items: center; padding: clamp(1.2rem, 4vw, 2rem) clamp(1.2rem, 5vw, 2.5rem); border-radius: 20px; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1rem; margin-top: 0.5rem; background: rgba(10, 10, 12, 0.65); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);">
    <div class="scanner-title-area" style="margin: 0;">
        <h1 class="text-gradient" style="margin-bottom: 0.35rem; font-size: clamp(1.6rem, 6vw, 2.25rem); letter-spacing: -0.02em; margin-top: 0; font-family: 'IBM Plex Sans', system-ui, sans-serif;">{word1} <span style="background: linear-gradient(135deg, var(--neo-blue), var(--neo-cyan)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">{word2}</span></h1>
        <p style="color: var(--neo-text-muted); font-size: 0.7rem; font-weight: 500; font-family: 'JetBrains Mono', monospace; margin: 0; display: flex; align-items: center; gap: 8px; opacity: 0.8; text-transform: uppercase;">
            <span style="height: 1px; width: 16px; background: linear-gradient(90deg, var(--neo-blue), transparent);"></span>
            {subtitle}
        </p>
    </div>
    
    <div class="flex gap-3">
        <a href="{{{{ url_for('tools_hub') }}}}" class="btn-dash" style="background: rgba(255,255,255,0.05); height: 38px; border-radius: 8px; padding: 0 1rem; display: flex; align-items: center; justify-content: center; gap: 0.4rem; color: var(--neo-text-muted); text-decoration: none; font-size: 0.75rem; border: 1px solid var(--neo-border);">
            <span class="material-symbols-outlined" style="font-size: 1.1rem;">home</span>
            <span style="font-family: 'JetBrains Mono', monospace; font-weight: 600; text-transform: uppercase;">Hub</span>
        </a>
    </div>
</div>\n\n"""
                new_content = content[:start_idx] + new_banner + content[end_idx:]
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(new_content)
                print(f"Updated Mobile: {os.path.basename(fpath)}")
            else:
                print(f"Regex failed for Mobile: {os.path.basename(fpath)}")

if __name__ == "__main__":
    process_desktop()
    process_mobile()
