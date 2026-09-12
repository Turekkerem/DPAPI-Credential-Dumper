# THE PROMISCUOUS, ENHANCED, AND HIGHLY SPECIFIC BEER-WARE NOTICE

> This is **not** a license. It is a set of non-binding requests that reflect
> the spirit of the project. The formal license for this repository is the
> **MIT License** — see [`LICENSE`](LICENSE). Nothing in this document
> modifies, extends, or restricts the MIT terms in any way.

< Turekkerem > wrote this code. As long as you retain the notice in `LICENSE`
and give appropriate credit to the original author, you can do whatever you
want with this stuff. You are free to use, modify, redistribute, study, or
print it out and frame it.

---

## 1. THE "DON'T BE A VILLAGE BIKE" REQUEST

Yes, the project is called *Promiscuous-CredsHarvester* because of how Windows
DPAPI implicitly trusts everything in the user session. However, that does not
mean you should treat this code the same way. Have some standards. Don't just
pass this tool around to every script kiddie on the block without context or
understanding of what it actually does. In other words: **don't be a village
bike**. Respect the code, read the source, understand the mechanics, and keep
it classy.

The MIT license already requires you to preserve attribution, so this section
is just a polite reminder that it exists — and that reading the source before
running it is a habit worth keeping.

---

## 2. THE "RÓBTA CO CHCETA" NOTICE

Let's be completely clear: this is an academic Proof of Concept credential
harvester. It touches sensitive APIs, decrypts master keys, and extracts
secrets. Because it can easily be weaponized for malicious purposes, the
software is provided **"as is"**, without warranty of any kind.

To the maximum extent permitted by applicable law, the author disclaims any
liability for damages arising from its use. If you misuse this tool, deploy it
without authorization, break the law, or end up in a government database, you
are entirely on your own. *Róbta co chceta* (do whatever you want) with the
code — but keep in mind that no license text can shield you from the
consequences of your own actions. This disclaimer does not extend to any
liability that cannot be excluded under applicable law.

---

## 3. THE BEER OBLIGATION (NON-BINDING, BUT SERIOUSLY)

Here's the deal. This is not a one-way street. I don't just give and give and
give while you sit there, quietly downloading my repository, nodding to
yourself, and never looking back. That's not how this works. That's not how
any of this works.

If we ever cross paths in person, and you've actually used this code, learned
from it, or deployed it in a successful engagement, and you genuinely think
the program is *git* — then buy me a beer. That's the deal. That's the whole
deal. No paperwork, no contract, no invoice. Just a beer between two people
who both understand what DPAPI is and why it's a problem.

**One condition, and this one is non-negotiable:** if you don't ask me which
beer I want, you're bringing me a non-alcoholic one. Because I'm crazy like
that. And no, I'm not joking. Ask first. It's a two-second question. The
answer might be a barrel-aged craft stout brewed by monks on a remote
mountain, or it might be a plain 0.0% lager. You don't get to decide. I do.

---

## 4. THE READ-AND-UNDERSTAND CLAUSE

This project is meant to be **read**. Not copy-pasted. Not blindly compiled.
Not thrown at a target and hoped for the best. Read.

Open `ChromiumDump.h` and look at how the DPAPI master key is unwrapped from
`Local State`. Open `FirefoxDump.h` and trace how the NSS `04 0E` IV prefix
is reconstructed. Read the comments. Look at the offsets. Understand why the
`VAULT_ITEM_WIN8` structure doesn't match what MSDN says.

Here's the honest part: **I would not be able to write this entire codebase
from scratch without the internet.** I rely on documentation, source code,
mailing lists, and — yes — AI assistance, just like everyone else who is
honest about it. But I *understand* what every module does. I understand why
each byte is where it is. I understand the failure modes. That's the bar.

If you can read this code and understand it, you're already ahead of the
people who just run tools they don't understand and hope for the best. If you
can't yet, that's fine — read it twice. Read it three times. Ask questions.
That's what the code is here for.

The goal is not to produce script kiddies. The goal is to produce people who
understand the mechanisms well enough to defend against them.

---

*Addendum to Section 3:*
The choice of said beer remains exclusively and non-negotiably mine. If you
don't ask, you're bringing non-alcoholic. I'm not being difficult — I'm being
consistent. Proceed with this notice only if you're prepared to ask a simple
question and accept the answer, whatever it is.