
# Run as Administrator
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

<#
Selection of record types. So far only A and CNAME Records
#>
do {
Write-Output "`n================= Pick a Record Type===================="
Write-Output "`t1. A Record"
Write-Output "`t2. CNAME Record"
Write-Output "`tq. to Quit"
Write-Output "========================================================"
$recordType = Read-Host "`nEnter Choice"
} until ( ($recordType -eq '1') -or ($recordType -eq '2') -or ($recordType -eq 'Q') )
switch ($recordType) {
   '1'{
       Write-Output "`nYou have selected to enter in an A Record"
   }
   '2'{
       Write-Output "`nYou have selected to enter in a CNAME Record"
   }
   'Q'{
      Return
   }
}

if (($recordType) -eq '1') {

    $recordType = 'A Record'

} else {

    $recordType = 'CNAME Record'

}

<#
To choose a server, only on-prem or cloudflare is available.
#>
do {
Write-Output "`n================== Pick a DNS Server==================="
Write-Output "`t1. On-prem"
Write-Output "`t2. CloudFlare"
Write-Output "`t3. Both"
Write-Output "`tq. to Quit"
Write-Output "========================================================"
$dnsServer = Read-Host "`nEnter Choice"
} until (($dnsServer -eq '1') -or ($dnsServer -eq '2') -or ($dnsServer -eq '3') -or ($dnsServer -eq 'Q') )
switch ($dnsServer) {
   '1'{
       Write-Output "`nYou have selected On-prem"
   }
   '2'{
       Write-Output "`nYou have selected CloudFlare"
   }
   '3'{
       Write-Output "`nYou have selected both On-prem and CloudFlare"
   }
   'Q'{
      Return
   }
}


if (($dnsServer) -eq '1') {

    $dnsServer = 'On-prem'
    Write-Output "`n========== Enter in Domain Details==============="
    Write-Output "`t1. Your Zone Name (domain.com)"
    Write-Output "========================================================"
    $zoneName = Read-Host 'Enter in you Zone Name'

} else {

    Write-Output "`n========== Enter in Cloudflare Details==============="
    Write-Output "`t1. Your Zone Name (domain.com)"
    Write-Output "`t2. Your Zone API Key"
    Write-Output "========================================================"
    $zoneName = Read-Host 'Enter in you Zone Name'
    $getSecureKey = Read-Host 'Enter in you Zone Key' -AsSecureString
    $CFAuthKey = [pscredential]::new('user',$getSecureKey).GetNetworkCredential().Password
    $apiRoot = 'https://api.cloudflare.com/client/v4/zones'
    $authHeader = @{'Authorization'="Bearer $CFAuthKey"} # 'X-Auth-Email'=$CFAuthEmail;'X-Auth-Key'=$CFAuthKey
    $zoneUrl = "$apiRoot/?name=$zoneName"

    # Get Zone ID info
    $zone = Invoke-RestMethod -Uri $zoneUrl -Method Get -Headers $authHeader
    $zoneID = $zone.result.id
    if (($zoneID) -eq $null) {
        Write-Output "`nWe did not find a zone, exiting...."
        Return
    } else {
        Write-Output "`nWe found your Zone ID: $zoneID"
    }

    if (($dnsServer) -eq '2') {
 
        $dnsServer = 'CloudFlare'

    } else {

        $dnsServer = 'Both'

    }

}
<#
Some edit options after selecting a server.
#>
if (($dnsServer) -eq 'On-prem') {


    if (($recordType) -eq 'A Record') {

        Write-Output "`n================== A Record====================="
        Write-Output "`tYou are entering in an A Record"
        Write-Output "`tq. to Quit"
        Write-Output "================================================"
        $RecordName = Read-Host "`nEnter the DNS Host record name"
        if (($RecordName -eq 'q') -or ($RecordName -eq 'Q')) {
            Return
        } else {
            Write-Output "`n`tHost Record: Your record is $RecordName.$zoneName"
        }
        $destinationrecord = Read-Host "`nEnter the destination IP address"
        if (($destinationrecord -eq 'q') -or ($destinationrecord -eq 'Q')) {
            Return
        } else {
            Write-Output "`n`tOn-prem Destination Record: Your record destination is $destinationrecord"
        }

    } else {

        Write-Output "`n================== CNAME Record=================="
        Write-Output "`tYou are entering in an CNAME Record"
        Write-Output "`tq. to Quit"
        Write-Output "================================================"
        $RecordName = Read-Host "`nEnter the DNS Host record name"
        if (($RecordName -eq 'q') -or ($RecordName -eq 'Q')) {
            Return
        } else {
            Write-Output "`n`tHost Record: Your record is $RecordName.$zoneName"
        }
        $destinationrecord = Read-Host "`nEnter the destination FQDN address"
        if (($destinationrecord -eq 'q') -or ($destinationrecord -eq 'Q')) {
            Return
        } else {
            Write-Output "`n`tOn-prem Destination Record: Your record destination is $destinationrecord"
        }

    }

} else {

    if (($dnsServer) -eq 'CloudFlare') {

        if (($recordType) -eq 'A Record') {

            Write-Output "`n================== A Record====================="
            Write-Output "`tYou are entering in an A Record"
            Write-Output "`tq. to Quit"
            Write-Output "================================================"
            $RecordName = Read-Host "`nEnter the DNS Host record name"
            if (($RecordName -eq 'q') -or ($RecordName -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tHost Record: Your record is $RecordName.$zoneName"
            }
            $RecordValue = Read-Host "`nEnter the destination IP address"
            if (($RecordValue -eq 'q') -or ($RecordValue -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tCloudFlare Destination Record: Your record destination is $RecordValue"
            }
            $proxyValue = Read-Host "`nDo you want to proxy via CloudFlare? (y/n) Default is (N)"
            if (($proxyValue -eq 'q') -or ($proxyValue -eq 'Q')) {
                Return
            } else {
                if (($proxyValue -eq 'y') -or ($proxyValue -eq 'Y')) {

                    Write-Output "`n`tYou have chosen to Proxy through CloudFlare"
                } else {

                    Write-Output "`n`tYou have chosen NOT to Proxy through CloudFlare"
                }
            }

        } else {

            Write-Output "`n================== CNAME Record=================="
            Write-Output "`tYou are entering in an CNAME Record"
            Write-Output "`tq. to Quit"
            Write-Output "================================================"
            $RecordName = Read-Host "`nEnter the DNS Host record name"
            if (($RecordName -eq 'q') -or ($RecordName -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tHost Record: Your record is $RecordName.$zoneName"
            }
            $RecordValue = Read-Host "`nEnter the destination FQDN address"
            if (($RecordValue -eq 'q') -or ($RecordValue -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tCloudFlare Destination Record: Your record destination is $RecordValue"
            }
            $proxyValue = Read-Host "`nDo you want to proxy via CloudFlare? (y/n) Default is (N)"
            if (($proxyValue -eq 'q') -or ($proxyValue -eq 'Q')) {
                Return
            } else {
                if (($proxyValue -eq 'y') -or ($proxyValue -eq 'Y')) {

                    Write-Output "`n`tYou have chosen to Proxy through CloudFlare"
                } else {

                    Write-Output "`n`tYou have chosen NOT to Proxy through CloudFlare"
                }
            }

        }

    } else {

        if (($recordType) -eq 'A Record') {

            Write-Output "`n================== A Record====================="
            Write-Output "`tYou are entering in an A Record"
            Write-Output "`tq. to Quit"
            Write-Output "================================================"
            $RecordName = Read-Host "`nEnter the DNS Host record name"
            if (($RecordName -eq 'q') -or ($RecordName -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tHost Record: Your record is $RecordName.$zoneName"
            }
            $destinationrecord = Read-Host "`nEnter the destination IP address on the on-prem DNS"
            if (($destinationrecord -eq 'q') -or ($destinationrecord -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tOn-prem Destination Record: Your record destination is $destinationrecord"
            }
            $RecordValue = Read-Host "`nEnter the destination IP address on the CloudFlare DNS"
            if (($RecordValue -eq 'q') -or ($RecordValue -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tCloudFlare Destination Record: Your record destination is $RecordValue"
            }
            $proxyValue = Read-Host "`nDo you want to proxy via CloudFlare? (y/n) Default is (N)"
            if (($proxyValue -eq 'q') -or ($proxyValue -eq 'Q')) {
                Return
            } else {
                if (($proxyValue -eq 'y') -or ($proxyValue -eq 'Y')) {

                    Write-Output "`n`tYou have chosen to Proxy through CloudFlare"
                } else {

                    Write-Output "`n`tYou have chosen NOT to Proxy through CloudFlare"
                }
            }
            

        } else {

            Write-Output "`n================== CNAME Record=================="
            Write-Output "`tYou are entering in an CNAME Record"
            Write-Output "`tq. to Quit"
            Write-Output "================================================"
            $RecordName = Read-Host "`nEnter the DNS Host record name"
            if (($RecordName -eq 'q') -or ($RecordName -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tHost Record: Your record is $RecordName.$zoneName"
            }
            $destinationrecord = Read-Host "`nEnter the destination FQDN address on the on-prem DNS"
            if (($destinationrecord -eq 'q') -or ($destinationrecord -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tOn-prem Destination Record: Your record destination is $destinationrecord"
            }
            $RecordValue = Read-Host "`nEnter the destination FQDN address on the CloudFlare DNS"
            if (($RecordValue -eq 'q') -or ($RecordValue -eq 'Q')) {
                Return
            } else {
                Write-Output "`n`tCloudFlare Destination Record: Your record destination is $RecordValue"
            }
            $proxyValue = Read-Host "`nDo you want to proxy via CloudFlare? (y/n) Default is (N)"
            if (($proxyValue -eq 'q') -or ($proxyValue -eq 'Q')) {
                Return
            } else {
                if (($proxyValue -eq 'y') -or ($proxyValue -eq 'Y')) {

                    Write-Output "`n`tYou have chosen to Proxy through CloudFlare"
                } else {

                    Write-Output "`n`tYou have chosen NOT to Proxy through CloudFlare"
                }
            }

        }

    }

}

# Change Proxy variable to $true or $false
if (($proxyValue -eq 'y') -or ($proxyValue -eq 'Y')) {
    $proxiedDNS = $true
} else {
    $proxiedDNS = $false
}

if (($recordType) -eq 'A Record') {

    if (($dnsServer) -eq 'On-prem') {

        #$dnsServer = 'On-prem'
        Add-DnsServerResourceRecordA -Name "$RecordName" -ZoneName "$zoneName" -AllowUpdateAny -IPv4Address "$destinationrecord" -TimeToLive 01:00:00
        Write-Output "`n`n================================================================================"
        Write-Output " Server: On-prem; Host: $RecordName.$zoneName; Destination: $destinationrecord"
        Write-Output "================================================================================"

    } else {

        if (($dnsServer) -eq 'CloudFlare') {

            #$dnsServer = 'CloudFlare'
            # check for an existing record
            $response = Invoke-RestMethod -Uri "$apiRoot/$zoneID/dns_records?type=A&name=$RecordName&content=$RecordValue" -Headers $authHeader -ContentType 'application/json' 

            # add the new A record if necessary
            if ($response.result.Count -eq 0) {

                $bodyJson = @{ type="A"; name=$RecordName; content=$RecordValue; proxied=$proxiedDNS; ttl=1 } | ConvertTo-Json
                Write-Verbose "Adding $RecordName with value $RecordValue"
                Invoke-RestMethod -Uri "$apiRoot/$zoneID/dns_records" -Method Post -Body $bodyJson -ContentType 'application/json' -Headers $authHeader | Out-Null

            } else {
                Write-Debug "Record $RecordName with value $RecordValue already exists. Nothing to do."
            }
            Write-Output "`n`n================================================================================"
            Write-Output "Server: CloudFlare; Host: $RecordName.$zoneName; Destination: $RecordValue; Proxied: $proxiedDNS"
            Write-Output "================================================================================"

        } else {

            #$dnsServer = 'Both'
            Add-DnsServerResourceRecordA -Name "$RecordName" -ZoneName "$zoneName" -AllowUpdateAny -IPv4Address "$destinationrecord" -TimeToLive 01:00:00
            # check for an existing record
            $response = Invoke-RestMethod -Uri "$apiRoot/$zoneID/dns_records?type=A&name=$RecordName&content=$RecordValue" -Headers $authHeader -ContentType 'application/json' 

            # add the new A record if necessary
            if ($response.result.Count -eq 0) {

                $bodyJson = @{ type="A"; name=$RecordName; content=$RecordValue; proxied=$proxiedDNS; ttl=1 } | ConvertTo-Json
                Write-Verbose "Adding $RecordName with value $RecordValue"
                Invoke-RestMethod -Uri "$apiRoot/$zoneID/dns_records" -Method Post -Body $bodyJson -ContentType 'application/json' -Headers $authHeader | Out-Null

            } else {
                Write-Debug "Record $RecordName with value $RecordValue already exists. Nothing to do."
            }
            Write-Output "`n`n================================================================================"
            Write-Output "Server: On-prem; Host: $RecordName.$zoneName; Destination: $destinationrecord"
            Write-Output "Server: CloudFlare; Host: $RecordName.$zoneName; Destination: $RecordValue; Proxied: $proxiedDNS"
            Write-Output "================================================================================"

        }

    }

} else {

    if (($dnsServer) -eq 'On-prem') {

        Add-DnsServerResourceRecordCName -Name "$RecordName" -HostNameAlias "$destinationrecord" -ZoneName "$zoneName"
        Write-Output "`n`n================================================================================"
        Write-Output "CNAME Record; Server: On-prem; Host: $RecordName.$zoneName; Destination: $destinationrecord"
        Write-Output "================================================================================"

    } else {

        if (($dnsServer) -eq 'CloudFlare') {

            # check for an existing record
            $response = Invoke-RestMethod -Uri "$apiRoot/$zoneID/dns_records?type=CNAME&name=$RecordName&content=$RecordValue" -Headers $authHeader -ContentType 'application/json' 

            # add the new A record if necessary
            if ($response.result.Count -eq 0) {

                $bodyJson = @{ type="CNAME"; name=$RecordName; content=$RecordValue; proxied=$proxiedDNS; ttl=1 } | ConvertTo-Json
                Write-Verbose "Adding $RecordName with value $RecordValue"
                Invoke-RestMethod -Uri "$apiRoot/$zoneID/dns_records" -Method Post -Body $bodyJson -ContentType 'application/json' -Headers $authHeader | Out-Null

            } else {
                Write-Debug "Record $RecordName with value $RecordValue already exists. Nothing to do."
            }
            Write-Output "`n`n================================================================================"
            Write-Output "CNAME Record; Server: CloudFlare; Host: $RecordName.$zoneName; Destination: $RecordValue; Proxied: $proxiedDNS"
            Write-Output "================================================================================"

        } else {

            Add-DnsServerResourceRecordCName -Name "$RecordName" -HostNameAlias "$destinationrecord" -ZoneName "$zoneName"
            # check for an existing record
            $response = Invoke-RestMethod -Uri "$apiRoot/$zoneID/dns_records?type=CNAME&name=$RecordName&content=$RecordValue" -Headers $authHeader -ContentType 'application/json' 

            # add the new A record if necessary
            if ($response.result.Count -eq 0) {

                $bodyJson = @{ type="CNAME"; name=$RecordName; content=$RecordValue; proxied=$proxiedDNS; ttl=1 } | ConvertTo-Json
                Write-Verbose "Adding $RecordName with value $RecordValue"
                Invoke-RestMethod -Uri "$apiRoot/$zoneID/dns_records" -Method Post -Body $bodyJson -ContentType 'application/json' -Headers $authHeader | Out-Null

            } else {
                Write-Debug "Record $RecordName with value $RecordValue already exists. Nothing to do."
            }
            Write-Output "`n`n================================================================================"
            Write-Output "CNAME Record; Server: On-prem; Host: $RecordName.$zoneName; Destination: $destinationrecord"
            Write-Output "CNAME Record; Server: CloudFlare; Host: $RecordName.$zoneName; Destination: $RecordValue; Proxied: $proxiedDNS"
            Write-Output "================================================================================"

        }

    }

}