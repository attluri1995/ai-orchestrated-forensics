# Git Repository Setup Guide

## ✅ Local Git Repository
Your local Git repository has been initialized and your first commit is ready!

## 🔗 Connect to Remote Repository

### Option 1: GitHub (Recommended)

1. **Create a new repository on GitHub:**
   - Go to https://github.com/new
   - Name it: `ai-orchestrated-forensics` (or any name you prefer)
   - Choose **Public** or **Private**
   - **DO NOT** initialize with README, .gitignore, or license (we already have these)
   - Click "Create repository"

2. **Connect your local repo to GitHub:**
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/ai-orchestrated-forensics.git
   git branch -M main
   git push -u origin main
   ```

   Replace `YOUR_USERNAME` with your GitHub username.

### Option 2: GitLab

1. **Create a new project on GitLab:**
   - Go to https://gitlab.com/projects/new
   - Name it: `ai-orchestrated-forensics`
   - Choose visibility level
   - **DO NOT** initialize with README
   - Click "Create project"

2. **Connect your local repo to GitLab:**
   ```bash
   git remote add origin https://gitlab.com/YOUR_USERNAME/ai-orchestrated-forensics.git
   git branch -M main
   git push -u origin main
   ```

### Option 3: Other Git Hosting (Bitbucket, etc.)

Follow similar steps - create a repository on your hosting service and add it as a remote.

## 📥 Clone on VM

Once your code is on GitHub/GitLab, you can clone it on any VM:

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ai-orchestrated-forensics.git
cd ai-orchestrated-forensics

# Install dependencies
pip install -r requirements.txt

# Test with sample data
python main.py analyze ./sample_data
```

## 🔄 Future Updates

After making changes, push them with:
```bash
git add .
git commit -m "Your commit message"
git push
```

## 🔍 Check Current Status

To see if you have a remote configured:
```bash
git remote -v
```

To see your current branch and status:
```bash
git status
```

