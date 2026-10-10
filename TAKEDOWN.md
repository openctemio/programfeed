# Takedown and removal requests

The programfeed collector reads public program information and, for the
platforms that allow it, redistributes it in a signed feed. If you run a
platform or a program and want your data out of the feed, or never in it,
this is how.

## Who can ask

- an authorised representative of a **platform** (to stop all records of the
  platform), or
- the owner or security contact of a **program** (to remove that program).

## How to ask

Email **security@openctem.io** with:

1. what to remove: the platform, or the program ids / program page URLs
   (the `id` field of the record, for example `bounty-targets:hackerone-example`);
2. who you are: write from an address on the platform's or the program's
   own domain, or from the security contact the program lists. We may ask
   you to confirm through a channel we can verify independently;
3. optionally, why, and any conditions under which you would allow
   inclusion later.

You do not need to cite a legal basis. We act on the request first and ask
questions second.

## What we commit to

| Step | Time |
|---|---|
| Acknowledge receipt | within 2 business days |
| Verify the request and stop publishing the records (merge the policy change, run the publish workflow) | within 72 hours of verification |
| Remove earlier published copies from the project's release assets | within 7 days |
| Confirm to you in writing | when done |

Subscribers pick the removal up through the feed itself: the next bundle
carries a `program_dropped` change for every removed program.

## How a platform is switched off

1. In `policy/platforms.json` set the platform's `publish` to `false` (add
   the platform with `publish: false` if it is not listed; an unlisted
   platform is never published).
2. The next build removes all of that platform's programs. It does this even
   for records already in the previous release: they are dropped with a
   `program_dropped` change instead of being kept as unchanged. A signed
   build also stops fetching that platform's data from aggregate datasets.
3. Run the publish workflow; delete the earlier release assets that contain
   the platform's records.

## How a single program is removed

Add its id to `excluded_programs` in `policy/platforms.json`. The program is
then never published, whichever source lists it, and is dropped from the
feed on the next build. For a self-hosted program that stays listed because
its security.txt exists, the exclusion keeps it out even though the file is
still there.

## Local copies

The collector can also build a local-only bundle (see the README). Those
bundles are made by whoever runs the tool, for their own use, and are not
published by this project. We cannot delete bundles that others built.

## Permission instead of removal

A platform that wants to be included, with specific attribution text or
conditions, tells us at **info@openctem.io**. We switch it to
`publish: true` only with the permission in writing.
