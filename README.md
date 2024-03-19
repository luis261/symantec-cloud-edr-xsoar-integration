This is the right code for you if you're planning on issuing EDR commands from XSOAR via calling endpoints of https://api.sep.securitycloud.symantec.com
> [!NOTE]
> see corresponding vendor documentation under https://apidocs.securitycloud.symantec.com/ > "Symantec™ Endpoint Security (SES)"; **so not the other Symantec EDR variant (which is hosted on prem, exposing API endpoints containing `/atpapi/`)** (the structure/routes of those APIs are NOT identical/closely related/easily interchangeable)  
> the non-cloud equivalent would be: https://github.com/demisto/content/tree/master/Packs/SymantecEDR/Integrations/SymantecEDR

## Setup

When creating a new instance of this integration, you'll need to provide the following required parameters:
- a target URL where the API routes are hosted (`https://api.sep.securitycloud.symantec.com` by default)
- an OAuth client token
> [!TIP]
> I had to prepend the OAuth token with `Basic ` to make it work

## Troubleshooting

> [!WARNING]
> you're getting 403's when testing an instance and you're sure it's not the creds?
> - you might have to switch your config to a more specific subdomain depending on your location, e.g. `https://api.sep.eu.securitycloud.symantec.com` instead of `https://api.sep.securitycloud.symantec.com`
> - the reason for the 403's is that the Python `requests` library strips auth headers on redirects to prevent leakage, so once your requests arrive at their destination, they're unauthenticated
> - if you're unsure what subdomain you need and can't figure it out by trial and error, it might make sense to either debug with curl (outside of XSOAR) or override `requests` functionality so that the prepared requests (containing the target host you're being redirected to) during redirects are emitted to a debug log
