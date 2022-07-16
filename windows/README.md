# Windows Scripts

This repository is all about Windows scripts that I have found along the way.

## add_dns_record

> ℹ️ Information
> This only works on the Windows DNS Server itself. You must also have a CloudFlare account and setup API Keys for the Zones that you are managed, we are **NOT** using the Global API

This PowerShell script comes from the frustration of having to manage public DNS records in two places; CloudFlare and On-prem DNS Servers. This is because I use a Traefik Reverse Proxy for a lot of things, including On-prem Sites/Services.
So the script will run through a few questions, so type in exactly what is needed, and not any extra fullstops or commas etc.
The script is a work-in-progress, but it does work as it is now - however, I would like to neaten it a bit since there are a lot of if/else statements with commandlets that could have been made variables to call...
