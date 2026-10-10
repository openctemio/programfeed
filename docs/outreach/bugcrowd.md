# Permission request to Bugcrowd

> **DRAFT. Not sent.** Review, confirm the recipient (partnerships or legal contact of Bugcrowd) and send from info@openctem.io. Keep the reply with the written permission in the repository history before changing `policy/platforms.json`.

**To:** Bugcrowd (partnerships / legal contact, to be confirmed before sending)
**From:** OpenCTEM team, info@openctem.io
**Subject:** Request for permission: referencing Bugcrowd public programs in the OpenCTEM program feed

Hello Bugcrowd team,

We are writing to ask for your written permission, or to be pointed to an official data path, before we publish anything that comes from Bugcrowd. Until we hear from you we publish nothing from Bugcrowd.

## Who we are

OpenCTEM (https://openctem.io, source at https://github.com/openctemio) is an open-source continuous threat exposure management platform that organisations run themselves. One of its modules lets an organisation follow public bug-bounty and vulnerability-disclosure programs: who runs a program, where the policy is, whether it pays, what scope the program publishes and how that scope changes. The collector that feeds it is open source: https://github.com/openctemio/programfeed.

## What data we would use

We would include the public engagement directory and the scope each public engagement publishes (engagement name, engagement page, bounty or no bounty, in-scope and out-of-scope targets, safe-harbour field, status). We would use only what is already visible to any visitor without an account: no private programs, no report data, no researcher data, no account-only fields.

Your website terms do not allow copying or redistribution of website content without permission, so we do not publish anything of yours today.

## How it would be used

- **Passive monitoring.** Subscribers read program information and are notified when a public program changes its scope or rules. The feed does not test, scan or contact anything.
- **Never an authorisation.** A scope entry in the feed states what the program lists. It is never presented as permission to test. Before any active testing of a program's assets, OpenCTEM requires the user to read the program's terms on Bugcrowd and attest that they accepted them and are eligible; targets taken from a listing are suggestions the user confirms.
- **Link back, attribution.** Every record names Bugcrowd as the original platform and links to the original program page, so users go to Bugcrowd for the authoritative, current terms. We show the attribution text you ask for wherever the data appears.
- **Careful reading.** Today the data reaches us through a public aggregate dataset on GitHub and we read it at a pinned commit. If you grant permission we would read only what you specify, identify ourselves with a descriptive User-Agent and contact address, honour robots.txt, use conditional requests and keep to at most one request per second.
- **Signed and verifiable.** The feed is published as a signed bundle; every record carries its provenance (source, commit, original platform, original program page, time read).

## Removal at any time

Any request to remove a program, or all of Bugcrowd, is handled under https://github.com/openctemio/programfeed/blob/main/TAKEDOWN.md: we acknowledge within 2 business days, stop publishing the records within 72 hours and delete earlier published copies. Contact: security@openctem.io.

## What we ask

1. Written permission to include Bugcrowd's public program listings (program name, program page, bounty yes/no, published scope, status) in the OpenCTEM program feed, which is publicly redistributed, under the attribution text and any conditions you specify; **or**
2. an official API or partner path for public program data, with its terms; **or**
3. a clear no, in which case Bugcrowd stays unpublished and we remove any local copies we hold.

If you would rather provide a feed or an API for public engagements, we will use that instead.

If it helps, we are glad to share a sample of exactly what a record looks like, or to schedule a short call.

Thank you for your time.

OpenCTEM team
info@openctem.io
