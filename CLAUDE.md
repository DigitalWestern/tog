# Working in this repo

- The independent review of every pull request is Codex GPT 6.1 Sol at
  high reasoning effort (`codex exec -m gpt-6.1-sol -c
  model_reasoning_effort="high"`), run through the alarm wrapper in
  the global CLAUDE.md with stdin closed. Its findings, and what was
  fixed or declined, go in the pull request description.

- After a pull request you worked on is merged, open a GitHub issue for
  every exception, problem, or needed fix you found along the way and did
  not ship in that PR: review findings, design questions raised in the
  discussion, missing tests. One issue per item, with the file paths, the
  options, and the one you would pick. Add a short pointer to each in
  FOLLOW-UPS.md so the repo's to-do list and the tracker agree.

# About Ethan

My name is Ethan. I work in finance at a private credit firm doing capital markets and origination, and software engineering is something I’ve taken up as a hobby on the side. I’ve built a number of smaller projects before this—mostly Python/data analysis, HTML/CSS, scripts, and other relatively straightforward projects—but Tog is my first large-scale backend/systems project. I am still very much a newcomer to Rust, systems programming, package managers, CI infrastructure, toolchains, dependency resolution, security, and many of the architectural concepts that appear throughout this codebase.

When working with me, do not assume that I understand terminology, conventions, or abstractions simply because they already exist in the codebase or because I have successfully built complicated parts of Tog. Much of this project has been written with substantial help from coding agents, so the sophistication of the code is significantly ahead of my own software-engineering knowledge. When explaining something, optimize for helping me actually understand it rather than sounding technically complete. Start with the simple mental model: what the thing is, why it exists, what problem it solves, and how it fits into Tog. Define unfamiliar terminology in plain English as you introduce it, and use concrete examples or analogies when they help. Then go deeper technically if necessary. I would much rather receive an explanation that initially feels almost embarrassingly simple than one that assumes background knowledge I don’t have. The goal is not merely to make changes to Tog for me; it is to help me gradually understand the system I am building.
