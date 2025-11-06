# SafeShare Development Scripts

This directory contains helper scripts for development. **This directory is ignored by git** - it won't be committed to the repository.

## Available Scripts

### 1. `new-branch.sh` - Interactive Branch Creator

Helps you create branches following the Git Flow strategy without memorizing the rules.

**Usage:**
```bash
./scripts/new-branch.sh
```

**What it does:**
- Asks what type of work you're doing (feature, bugfix, docs, hotfix, release)
- Prompts for a descriptive branch name
- Automatically checks out the correct base branch (develop or main)
- Pulls the latest changes
- Creates and checks out your new branch
- Shows you the next steps

**Example workflow:**
```bash
$ ./scripts/new-branch.sh

? What are you working on?
  1) New feature          (branches from: develop)
  2) Bug fix              (branches from: develop)
  ...

Enter your choice: 1
Enter a descriptive name: Add Email Notifications

✓ Created and switched to branch: feature/add-email-notifications
```

### 2. `create-release.sh` - Version Tagging Helper

Helps you create properly formatted release tags with automatic version bumping.

**Usage:**
```bash
./scripts/create-release.sh
```

**What it does:**
- Shows current version
- Asks if you want major, minor, or patch bump
- Creates annotated tag with release notes
- Pushes tag to trigger CI/CD

### 3. `cleanup-branches.sh` - Branch Cleanup Helper

Helps you delete branches after they've been merged. No more stale branches cluttering your repository!

**Usage:**
```bash
./scripts/cleanup-branches.sh
```

**What it does:**
- Delete a specific local branch
- Clean up all merged branches at once (safe!)
- List all branches to see what exists
- Delete remote branches
- Prevents accidental deletion of main/develop
- Warns if branch has unmerged changes

**Example workflows:**

**After merging a PR:**
```bash
$ ./scripts/cleanup-branches.sh

? What would you like to clean up?
  1) Delete a specific local branch
  2) Clean up all merged branches (safe - only deletes already merged)

Enter your choice: 1
Enter branch name: docs/update-readme-with-screenshots

✓ Deleted local branch: docs/update-readme-with-screenshots
? Remote branch also exists. Delete it? (y/n): y
✓ Deleted remote branch: origin/docs/update-readme-with-screenshots
```

**Spring cleaning:**
```bash
$ ./scripts/cleanup-branches.sh

Enter your choice: 2

The following branches have been merged:
  → feature/add-qr-codes
  → bugfix/cookie-security
  → docs/update-readme

Delete all these branches? (y/n): y
✓ Deleted: feature/add-qr-codes
✓ Deleted: bugfix/cookie-security
✓ Deleted: docs/update-readme
```

## Git Flow Quick Reference

### Branch Types

| Branch Type | Prefix | Base Branch | Purpose |
|-------------|--------|-------------|---------|
| Feature | `feature/` | `develop` | New functionality |
| Bugfix | `bugfix/` | `develop` | Non-critical bug fixes |
| Documentation | `docs/` | `develop` | Documentation updates |
| Hotfix | `hotfix/` | `main` | Critical production bugs |
| Release | `release/` | `develop` | Release preparation |

### Workflow

1. **Start work**: `./scripts/new-branch.sh`
2. **Make changes**: Edit files, commit regularly
3. **Push**: `git push origin your-branch-name`
4. **Create PR**: On GitHub, merge into `develop` (or `main` for hotfixes)
5. **Release**: When ready, use `./scripts/create-release.sh`

## Tips

- **Feature branches**: Always branch from and merge to `develop`
- **Hotfixes**: Branch from `main`, merge to both `main` AND `develop`
- **Releases**: Merge `develop` → `main`, tag, then sync back to `develop`
- **Small changes**: Direct commits to `develop` are okay for typos/docs
- **Never commit directly to `main`**: Branch protection prevents this

## Adding Your Own Scripts

Feel free to add your own development helper scripts to this directory. They won't be committed to the repository.

Some ideas:
- Database reset script
- Test data seeding
- Local deployment automation
- Backup scripts
