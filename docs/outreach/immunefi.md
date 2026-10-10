# Permission request to Immunefi

> **DRAFT. Not sent.** Review, confirm the recipient (partnerships or legal contact of Immunefi) and send from info@openctem.io. Keep the reply with the written permission in the repository history before changing `policy/platforms.json`.

**To:** Immunefi (partnerships / legal contact, to be confirmed before sending)
**From:** OpenCTEM team, info@openctem.io
**Subject:** Request for permission: referencing Immunefi public programs in the OpenCTEM program feed

Hello Immunefi team,

We are writing to ask for your written permission, or to be pointed to an official data path, before we publish anything that comes from Immunefi. Until we hear from you we publish nothing from Immunefi.

## Who we are

OpenCTEM (https://openctem.io, source at https://github.com/openctemio) is an open-source continuous threat exposure management platform that organisations run themselves. One of its modules lets an organisation follow public bug-bounty and vulnerability-disclosure programs: who runs a program, where the policy is, whether it pays, what scope the program publishes and how that scope changes. The collector that feeds it is open source: https://github.com/openctemio/programfeed.

## What data we would use

We would include the public bug-bounty directory and the assets in scope of each public bounty (project name, bounty page, rewards present or not, in-scope assets such as websites and smart-contract addresses, status). We would use only what is already visible to any visitor without an account: no private programs, no report data, no researcher data, no account-only fields.

Your terms of use do not allow automated access to the website without written consent, so we do not read your website and we do not publish anything of yours today.

## How it would be used

- **Passive monitoring.** Subscribers read program information and are notified when a public program changes its scope or rules. The feed does not test, scan or contact anything.
- **Never an authorisation.** A scope entry in the feed states what the program lists. It is never presented as permission to test. Before any active testing of a program's assets, OpenCTEM requires the user to read the program's terms on Immunefi and attest that they accepted them and are eligible; targets taken from a listing are suggestions the user confirms.
- **Link back, attribution.** Every record names Immunefi as the original platform and links to the original program page, so users go to Immunefi for the authoritative, current terms. We show the attribution text you ask for wherever the data appears.
- **Careful reading.** Today we do not read this platform at all. If you grant permission we would read only what you specify, identify ourselves with a descriptive User-Agent and contact address, honour robots.txt, use conditional requests and keep to at most one request per second.
- **Signed and verifiable.** The feed is published as a signed bundle; every record carries its provenance (source, commit, original platform, original program page, time read).

## Removal at any time

Any request to remove a program, or all of Immunefi, is handled under https://github.com/openctemio/programfeed/blob/main/TAKEDOWN.md: we acknowledge within 2 business days, stop publishing the records within 72 hours and delete earlier published copies. Contact: security@openctem.io.

## What we ask

1. Written permission to include Immunefi's public program listings (program name, program page, bounty yes/no, published scope, status) in the OpenCTEM program feed, which is publicly redistributed, under the attribution text and any conditions you specify; **or**
2. an official API or partner path for public program data, with its terms; **or**
3. a clear no, in which case Immunefi stays unpublished and we remove any local copies we hold.

If you can share written consent for reading your public bounty listing, or point us to a data path made for this, we would use only that.

If it helps, we are glad to share a sample of exactly what a record looks like, or to schedule a short call.

Thank you for your time.

OpenCTEM team
info@openctem.io
