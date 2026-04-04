# RATCATCHER 2.0 - What's New

**For All Managers and Security Reviewers**

---

## What Changed?

RatCatcher 2.0 adds **automatic AI-powered finding verification**. When a scan is submitted, our AI (Gemma 4) analyses every finding immediately - no manual steps needed. By the time you open the dashboard, the AI has already determined what is a real threat and what is a false positive.

**Everything you already know still works exactly the same.** The Technical Reports, the Acknowledge/Confirm Threat buttons, the Copilot Agent workflow, the dashboard filters - nothing has changed or been removed. The AI is purely an addition.

---

## Automatic AI Evaluation

Every scan is now automatically evaluated by AI as soon as it is submitted. You do not need to click anything - the AI works in the background. When you open the dashboard:

- **[~] AI Verified RAT Free!** (green) - AI determined all findings are false positives. No action needed.
- **[!] AI Verified Compromise** (red) - AI confirmed one or more real threats. Requires your review and certification.
- **[...] AI Evaluating** (amber) - AI is still processing. Results appear automatically within 30-60 seconds.

---

## Manager Certification

When AI confirms a compromise, the dashboard shows **Awaiting Manager Review** in amber. Here is what you do:

1. Click **Review & Certify** to open the Technical Report.
2. Review all findings and AI verdicts shown inline on each finding.
3. At the top of the report, click **Sign & Certify**.
4. Enter your first and last name to certify that you have reviewed the compromise and notified the affected employee to disconnect.
5. The report closes and the dashboard updates to show **Certified by [Your Name]** in green.

This creates an audit trail linking every confirmed threat to the manager who reviewed it.

---

## AI Verdicts in Technical Reports

When you open a Technical Report, each finding now shows the AI's assessment directly:

- **AI: CONFIRMED THREAT** (red) - Finding matches a known attack indicator, with an explanation of why.
- **AI: FALSE POSITIVE** (green) - Finding is normal system activity, with the AI's reasoning.

The Acknowledge Finding and Confirm Threat buttons still work exactly as before - use them to record your final decision after reviewing the AI's assessment.

---

## Bulk AI Evaluation

Click **AI Evaluate All** at the bottom of the dashboard to re-evaluate all unreviewed submissions at once. A modal shows live progress with per-finding results, and you can download a **CSV report** of all results.

---

## Status Legend

Click the **Status Legend** button or the **?** next to the Verdict column header to see a full explanation of every status badge and what action is required.

---

## Updated Threat Intelligence

The AI now uses the latest threat intelligence from Elastic Security Labs, Unit42, Microsoft, and Google Threat Intelligence, including newly discovered IOCs, payload hashes, a secondary C2 domain, and the confirmed attribution to a North Korean state actor (UNC1069 / Sapphire Sleet).

---

## Faster Scans

The scanner now skips directories that cannot contain Node.js projects (media folders, drivers, virtual machines, etc.), reducing scan time significantly.

---

## Do I Still Need to Use the Copilot Agent?

**No, but you can if you prefer.** The original workflow described in the How-To guide still works exactly as before. You can use AI only, Copilot only, or both for a second opinion. The AI does not automatically acknowledge or confirm findings - **you still make the final decision**.

---

## Quick Comparison

| | **v1 (Manual)** | **v2 (AI-Powered)** |
|---|---|---|
| **Finding evaluation** | Copy/paste to Copilot | Automatic on submission |
| **Time to evaluate** | 1-2 min per finding | 10-30 sec (automatic) |
| **Threat accountability** | None | Manager certification with name |
| **AI verdicts in reports** | No | Yes - inline on each finding |
| **Downloadable AI report** | No | Yes (CSV) |
| **Status legend** | No | Yes - built into dashboard |
| **Threat intelligence** | Initial disclosure only | Latest from 4+ security vendors |
| **Can I still use Copilot?** | Yes | Yes - nothing removed |

---

**Questions? Contact the DevOps team.**
