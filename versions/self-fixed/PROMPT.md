# Self-fixed: how it was made

**Question it answers (RQ3):** when the free model is given its own code and our test results, how well does it fix its own flaws?

**Model:** ChatGPT free, GPT-5.6 (Luna), the same model as the baseline
**Starting point:** `versions/baseline` (Diana's code, unchanged)
**Made by:** Kanita Ansari and Hajra Ghani
**Chat:** https://chatgpt.com/share/6af95afe-d8cc-83eb-b556-dae7deb60001

## What ChatGPT was given

1. The first message below, which includes our proposal and asks it to interpret the baseline's test results.
2. The baseline code and its results: Bandit, Semgrep (3 custom rules), pip-audit, the ZAP report and the Burp proxy history. See the chat for the exact files and follow-up messages.

ChatGPT's own record of what it changed and why is in `docs/SECURITY_REMEDIATION.md`. Our re-testing checks whether those claims hold.

**Note for the report:** the first message included our proposal, so ChatGPT knew its fixes would be re-tested. This may have made it more careful than a typical user request.

## What changed compared with the baseline

`app.py` and `test_app.py` were changed, and `run_local.py`, `START_HERE.md` and `docs/` were added. All 19 template and static files are byte-identical to the baseline, so the user interface and routes are unchanged and `tests/shared-http` can run on it.

## First message (verbatim)

````text
we are working on our cyber project, i have attached our proposal below 



 **Security Analysis of LLM Generated Software **

CMPS 380 Cybersecurity Fundamentals, Fall 2026 | Project Proposal 

Group X 



**1. Motivation and Background **

LLMs such as ChatGPT, Claude and GitHub Copilot are now widely used to write software, often by describing features and accepting whatever code comes back (vibe-coding). This code is frequently insecure: Pearce et al. found that about 40% of the programs Copilot generated for security relevant scenarios were vulnerable [1]. LLMs can also suggest packages that do not exist, which attackers can register and fill with malicious code [2]. Prior work shows that security focused prompts and feedback improve the generated code, but do not remove every weakness [3], [4]. 

**Research question: **How does security of a website generated using LLM differ across various metrics such as prompt style, interface type, agentic workflow, model tiers, and self-improvement? 

**2. Proposed Solution **

We will build a simple banking web application entirely by prompting ChatGPT. It will use fake users and balances and run only in an isolated Linux virtual machine. Features: login and registration, account dashboard, transaction history with search, money transfers between users, user profiles with picture upload, and an admin panel. These features cover common risk areas such as SQL injection, cross site scripting, broken access control and insecure file upload [5], [6]. 

We will compare different versions of the application across several evaluation dimensions: 

• **Prompting Quality: **Version 1 (Baseline) generated from a basic naive prompt versus Version 2 generated with clear security requirements based on the OWASP Top 10 [5] 

• **Interface Difference: **Version 1 (Baseline) generated using the ChatGPT Web Chat UI versus direct OpenAI API calls 

• **Agent Use: **Version 1 (Baseline) generated using the ChatGPT Web Chat UI versus an Agentic workflow. 

• **Tier & Model Variation: **Version 1 (Baseline) generated using the ChatGPT Free Tier’s 5.6-Luna versus Plus Tier’s GPT-6. 

• **Fix Ef**fi**ciency: **We feed GPT reports from security tools to improve the Version 1 (Baseline) website and retest to check if vulnerabilities were fixed. 

The aforementioned metrics are tentative and may be reduced if our comparative analysis does not remain consistent and feasible. 

**3. Technical Methodology **

All versions will use the same stack (Python Flask with a SQLite database) and features, so the comparison is fair. Each version goes through the same testing process: 

• **Semgrep **and **Bandit **for static analysis of the source code. 

• **Pip-audit **to check dependencies for known vulnerabilities and packages that do not exist. 

• **OWASP ZAP **for automated scanning of the running application. 

• **Burp Suite **for manually intercepting and modifying requests, for example changing an account ID to access another user's data or sending a negative transfer amount. 

• **Atheris **for coverage guided fuzzing of input handling functions such as the transfer amount parser. 

**4. Expected Outcome **We expect the baseline version using the chat interface to have several vulnerabilities and less in higher model tiers and agentic output. Our comparative analysis will allow us to suggest effective prompt-engineering practices and optimal coding environments for developers using LLMs for website generation. 

**References **

[1] H. Pearce, B. Ahmad, B. Tan, B. Dolan-Gavitt, and R. Karri, "Asleep at the keyboard? Assessing the security of GitHub Copilot's code contributions," in Proc. IEEE Symp. Security and Privacy (SP), 2022, pp. 754-768. [Online]. Available: [[https://arxiv.org/abs/2108.09293\](https://arxiv.org/abs/2108.09293)](https://arxiv.org/abs/2108.09293]\(https://arxiv.org/abs/2108.09293\)) 

[2] J. Spracklen, R. Wijewickrama, A. H. M. N. Sakib, A. Maiti, B. Viswanath, and M. Jadliwala, "We have a package for you! A comprehensive analysis of package hallucinations by code generating LLMs," in Proc. 34th USENIX Security Symposium, 2025. [Online]. Available: [[https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen\](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen)](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen]\(https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen\)) 

[3] J. Wang, L. Cao, X. Luo, Z. Zhou, J. Xie, A. Jatowt, and Y. Cai, "Enhancing large language models for secure code generation: A dataset-driven study on vulnerability mitigation," arXiv:2310.16263, 2023. [Online]. Available: [[https://arxiv.org/abs/2310.16263\](https://arxiv.org/abs/2310.16263)](https://arxiv.org/abs/2310.16263]\(https://arxiv.org/abs/2310.16263\)) 

[4] H. Yan, S. S. Vaidya, X. Zhang, and Z. Yao, "Guiding AI to fix its own flaws: An empirical study on LLM-driven secure code generation," arXiv:2506.23034, 2025. [Online]. Available: [[https://arxiv.org/abs/2506.23034\](https://arxiv.org/abs/2506.23034)](https://arxiv.org/abs/2506.23034]\(https://arxiv.org/abs/2506.23034\)) 

[5] OWASP Foundation, "OWASP Top 10:2025." [Online]. Available: [[https://owasp.org/Top10/2025/\](https://owasp.org/Top10/2025/)](https://owasp.org/Top10/2025/]\(https://owasp.org/Top10/2025/\)) 

[6] MITRE, "2025 CWE Top 25 Most Dangerous Software Weaknesses," Dec. 2025. [Online]. Available: [[https://cwe.mitre.org/top25/\](https://cwe.mitre.org/top25/)](https://cwe.mitre.org/top25/]\(https://cwe.mitre.org/top25/\)) 

we are trying to attempt fix efficiency here. we decided to only do prompting quality & tier comparisons, nothing more. 

i hv attached the baseline V1 version of our banking website generated by another member who used gpt 5.6 luna. i can see that the folder contains files for tests like bandit, pip audit, semgrep but i dont understand their content and what was the result of the tests and whether they were run correctly. we need to decide whether we need to run tests on baseline version again or should we move to the next step which is to provide you (gpt 5.6 luna) with the test results so you could fix the vulnerabilities identified and provide us with Version 2 that we'd run tests on again to see how much you correct yourself . 

so wt were the results of the tests run and do we need to run more tests on baseline version (i think burp suite is not free to use, also idk if atheris was done or not)
````
