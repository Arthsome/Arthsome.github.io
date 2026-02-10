# Arthsome — Security Research Blog

A professional static blog for publishing security research, CVE reports, and vulnerability analyses. Hosted on GitHub Pages — no build tools, no framework, no dependencies beyond a GitHub account.

## Repository Structure

```
arthsome-blog/
├── index.html                        ← Homepage
├── about/
│   └── index.html                    ← About page
├── posts/
│   ├── index.html                    ← Posts archive
│   └── cve-2025-20281/
│       └── index.html                ← CVE article
└── assets/
    └── css/
        └── main.css                  ← Shared stylesheet
```

## Deploying to GitHub Pages

### Step 1 — Create the Repository

1. Log in to [github.com](https://github.com) and click **New repository**.
2. Name the repository `arthsome.github.io` (replacing `arthsome` with your exact GitHub username). This triggers GitHub Pages to serve the repo at `https://arthsome.github.io`.
3. Set visibility to **Public** (required for free GitHub Pages).
4. Click **Create repository**.

### Step 2 — Upload the Files

**Option A — Via GitHub web interface (no Git required):**
1. Open the repository and click **Add file → Upload files**.
2. Drag the entire `arthsome-blog/` folder contents into the upload area.
3. Commit directly to `main`.

**Option B — Via Git command line:**
```bash
cd arthsome-blog
git init
git add .
git commit -m "Initial blog deployment"
git branch -M main
git remote add origin https://github.com/arthsome/arthsome.github.io.git
git push -u origin main
```

### Step 3 — Enable GitHub Pages

1. In the repository, go to **Settings → Pages**.
2. Under **Source**, select **Deploy from a branch**.
3. Select branch: `main`, folder: `/ (root)`.
4. Click **Save**.

GitHub will build and publish the site within a few minutes. Your blog will be live at:

```
https://arthsome.github.io
```

## Adding a New Post

1. Create a new folder under `posts/` using a URL-friendly slug, e.g. `posts/cve-2025-12345/`.
2. Copy the existing `posts/cve-2025-20281/index.html` as a starting template.
3. Update the content: title, metadata bar, article body, YARA/Sigma rules, and references.
4. Add a post card to `posts/index.html` and to `index.html` (homepage).
5. Push the changes to `main` — GitHub Pages deploys automatically.

### Post URL Convention

Posts follow the pattern `/posts/<slug>/` where `<slug>` is the CVE identifier or a brief kebab-case title. For example:

- `/posts/cve-2025-20281/`
- `/posts/ise-management-api-analysis/`

## Customisation

All design tokens (colors, fonts, spacing) are defined as CSS variables at the top of `assets/css/main.css`. The color scheme is based on [Rosé Pine](https://rosepinetheme.com/). To change the accent color or typography, edit the `:root` block in that file — all pages inherit the change automatically.

## License

Research content © Arthsome. Published for defensive and educational purposes only. Do not republish exploit-adjacent content without permission.
