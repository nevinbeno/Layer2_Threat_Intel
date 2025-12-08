# Repo Usage Guidelines
### Please note: 
- Please create and work in your own branches
- `main` branch is protected. Only PRs (Pull Requests) can update `main`
_____
#### Daily Workflow: 
1. Update your local main
```bash
$ git checkout main
$ git pull
```
2. Sync changes into your branch
```bash
$ git checkout <your_branch_name>
$ git merge main
```
3. Do your work: Code -> Commit -> Push **IN YOUR BRANCH**
_______
### Once someone's job is done
- Create a PR. 
- **The team** can review / comment. 
- Merge

Hence, main is updated safely. 