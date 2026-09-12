# Legal Disclaimer & Authorized Use Policy

AutoVAPT is built and published strictly for **educational purposes** and
for use in **authorized security assessments**.

By using this tool you agree that:

1. You will **only** run it against systems you own, or systems for which
   you have **explicit, documented, written authorization** to test
   (e.g. a signed pentest engagement letter / rules of engagement).
2. You understand that unauthorized scanning, probing, or testing of
   computer systems is **illegal** in most jurisdictions, including:
   - the U.S. Computer Fraud and Abuse Act (CFAA)
   - the UK Computer Misuse Act 1990
   - India's Information Technology Act, 2000 (Sections 43 & 66)
   - equivalent legislation in other countries
3. The author(s) of this project accept **no liability** for misuse of
   this tool. It is provided "as is", without warranty of any kind.
4. This tool performs **non-destructive** reconnaissance, enumeration,
   and indicator-based vulnerability detection only. It does **not**
   perform exploitation, credential theft, password cracking against
   real systems, data deletion, persistence, malware deployment, or
   automated RCE. It is not a substitute for manual verification by a
   qualified penetration tester before any finding is reported as
   confirmed.

**Recommended safe practice targets for learning:**
- Your own local lab (`examples/lab_server.py`, VirtualBox/VMware VMs, Docker containers)
- Deliberately vulnerable applications: DVWA, bWAPP, OWASP Juice Shop,
  Metasploitable2/3, OWASP crAPI
- Legal bug bounty programs with an in-scope policy (HackerOne, Bugcrowd)
- `scanme.nmap.org` (explicitly permitted by Nmap's authors for basic
  port-scan testing only — do not run intrusive modules against it)

If in doubt, don't scan it.
