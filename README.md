This is the right code for you if you're planning on issuing EDR commands from XSOAR via calling endpoints of https://api.sep.securitycloud.symantec.com
> https://apidocs.securitycloud.symantec.com/ > "Symantec™ Endpoint Security (SES)"; **so not the other Symantec EDR variant (which is hosted on prem, exposing API endpoints containing `/atpapi/`)** (the structure/routes of those APIs is NOT identical/related/easily interchangeable)  
the non-cloud equivalent would be: https://github.com/demisto/content/tree/master/Packs/SymantecEDR/Integrations/SymantecEDR
