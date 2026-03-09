# Copyright (c) 2024-2026 e1z0, EFN LAB01. All Rights Reserved.
#
# RouterOS v7 DHCP lease-script for Technitium DNS synchronization.
# Creates/removes forward A and reverse PTR records on lease bind/unbind.
# Includes hostname sanitization, dynamic PTR zone detection, and API debug mode.
#
# Required DHCP setup:
# 1) Create/import this script as: dhcp-to-technitium_v2
# 2) Attach it to DHCP server lease-script, e.g.:
#    /ip dhcp-server set [find where name="dhcp-servers"] lease-script="dhcp-to-technitium_v2"
# 3) DHCP lease events must provide leaseBound, leaseActIP, leaseServerName variables.
#
# Change these CONFIG values for your environment:
# - debug        true/false for verbose API logging
# - domain       forward DNS zone suffix used in FQDNs (example: lab01.domain.com)
# - zone         Technitium forward zone (example: domain.com)
# - dnsApiUrl    Technitium API base URL (example: https://dns.domain.com/api/zones/records)
# - apiKey       Technitium API token
# - DHCPtag      comment marker written to Technitium records
# - leaseServerName->prefix mappings if your DHCP server names differ

# CONFIG
:local DHCPtag "#LAB01#DHCP2DNS#"
:local LogPrefix ("DHCP2DNS (" . $leaseServerName . ")")
:local debug true
:local domain "lab01.domain.com"
:local zone "domain.com"
:local dnsApiUrl "https://dns.domain.com/api/zones/records"
:local apiKey "secret"
:local prefix "none"

# HELPER FUNCTIONS
:local logDebug do={
    :local msg $1
    :if ($debug = true) do={
        :log info ($LogPrefix . ": " . $msg)
    }
}

:local trimString do={
    :local inStr $1
    :local outStr ""
    :for i from=0 to=([:len $inStr] - 1) do={
        :local ch [:pick $inStr $i ($i + 1)]
        :if (($ch != " ") and ($ch != "\00")) do={
            :set outStr ($outStr . $ch)
        }
    }
    :return $outStr
}

# "a.b.c.d" -> "a-b-c-d"
:local ipToDashed do={
    :local inStr $1
    :local outStr ""
    :for i from=0 to=([:len $inStr] - 1) do={
        :local ch [:pick $inStr $i ($i + 1)]
        :if ($ch = ".") do={ :set ch "-" }
        :set outStr ($outStr . $ch)
    }
    :return $outStr
}

# lowercase, allow only a-z 0-9 -, collapse repeated -, trim - at ends
:local sanitizeHostname do={
    :local inStr $1
    :local lower [:convert $inStr transform=lc]
    :local allowed "abcdefghijklmnopqrstuvwxyz0123456789-"
    :local outStr ""
    :local prevDash false

    :for i from=0 to=([:len $lower] - 1) do={
        :local ch [:pick $lower $i ($i + 1)]
        :if ([:find $allowed $ch] != nil) do={
            :set outStr ($outStr . $ch)
            :set prevDash false
        } else={
            :if ($prevDash = false) do={ :set outStr ($outStr . "-") }
            :set prevDash true
        }
    }

    :while (([:len $outStr] > 0) and ([:pick $outStr 0 1] = "-")) do={
        :set outStr [:pick $outStr 1 [:len $outStr]]
    }
    :while (([:len $outStr] > 0) and ([:pick $outStr ([:len $outStr] - 1) [:len $outStr]] = "-")) do={
        :set outStr [:pick $outStr 0 ([:len $outStr] - 1)]
    }

    :return $outStr
}

# a.b.c.d -> b.a.in-addr.arpa
:local getPtrZone do={
    :local ipAddress $1
    :local firstDot [:find $ipAddress "."]
    :local secondDot [:find $ipAddress "." ($firstDot + 1)]
    :if (($firstDot = nil) or ($secondDot = nil)) do={ :return "" }
    :local octet1 [:pick $ipAddress 0 $firstDot]
    :local octet2 [:pick $ipAddress ($firstDot + 1) $secondDot]
    :return ($octet2 . "." . $octet1 . ".in-addr.arpa")
}

# a.b.c.d -> d.c.b.a.in-addr.arpa
:local getReverseFqdn do={
    :local ipAddress $1
    :local firstDot [:find $ipAddress "."]
    :local secondDot [:find $ipAddress "." ($firstDot + 1)]
    :local thirdDot [:find $ipAddress "." ($secondDot + 1)]
    :if (($firstDot = nil) or ($secondDot = nil) or ($thirdDot = nil)) do={ :return "" }
    :local octet1 [:pick $ipAddress 0 $firstDot]
    :local octet2 [:pick $ipAddress ($firstDot + 1) $secondDot]
    :local octet3 [:pick $ipAddress ($secondDot + 1) $thirdDot]
    :local octet4 [:pick $ipAddress ($thirdDot + 1) [:len $ipAddress]]
    :return ($octet4 . "." . $octet3 . "." . $octet2 . "." . $octet1 . ".in-addr.arpa")
}

# MAIN LOGIC
:if ([:len $leaseActIP] <= 0) do={
    :log error ($LogPrefix . ": empty lease address")
    :error "empty lease address"
}

:set prefix "none"
:if ($leaseServerName = "dhcp-legacy") do={ :set prefix "legacy" }
:if ($leaseServerName = "dhcp-cameras") do={ :set prefix "cameras" }
:if ($leaseServerName = "dhcp-guests") do={ :set prefix "guests" }
:if ($leaseServerName = "dhcp-iot") do={ :set prefix "iot" }
:if ($leaseServerName = "dhcp-mgmt") do={ :set prefix "mgmt" }
:if ($leaseServerName = "dhcp-secret") do={ :set prefix "secret" }
:if ($leaseServerName = "dhcp-servers") do={ :set prefix "servers" }
:if ($leaseServerName = "dhcp-users") do={ :set prefix "users" }
:if ($leaseServerName = "dhcp-voip") do={ :set prefix "voip" }
:if (($prefix = "none") and ([:len $leaseServerName] > 5) and ([:pick $leaseServerName 0 5] = "dhcp-")) do={
    :set prefix [:pick $leaseServerName 5 [:len $leaseServerName]]
}
:if ($prefix = "none") do={ :set prefix $leaseServerName }

:local ptrZone [$getPtrZone $leaseActIP]
:if ([:len $ptrZone] <= 0) do={
    :log error ($LogPrefix . ": cannot build PTR zone from " . $leaseActIP)
    :error "invalid ptrzone"
}

:local reverseFqdn [$getReverseFqdn $leaseActIP]
:if ([:len $reverseFqdn] <= 0) do={
    :log error ($LogPrefix . ": cannot build reverse FQDN from " . $leaseActIP)
    :error "invalid reverse fqdn"
}

:if ($leaseBound = 1) do={
    /ip dhcp-server lease
    :local leaseId [find where address=$leaseActIP]
    :if ([:len $leaseId] != 1) do={
        :log warning ($LogPrefix . ": Multiple active DHCP leases for '" . $leaseActIP . "' (???)")
        :error ("Multiple active DHCP leases for '" . $leaseActIP . "' (???)")
    }

    :local hostnameRaw $"lease-hostname"
    :if ([:len $hostnameRaw] <= 0) do={
        :set hostnameRaw [get $leaseId host-name]
    }
    :local hostname [$trimString $hostnameRaw]
    :set hostname [$sanitizeHostname $hostname]
    :if ([:len $hostname] <= 0) do={
        :set hostname [$ipToDashed $leaseActIP]
        :set hostname [$sanitizeHostname $hostname]
        :if ([:len $hostname] <= 0) do={ :set hostname [$ipToDashed $leaseActIP] }
        :log info ($LogPrefix . ": Empty hostname for '" . $leaseActIP . "', using generated host name '" . $hostname . "'")
    }

    :local generatedHostname [$ipToDashed $leaseActIP]
    :set generatedHostname [$sanitizeHostname $generatedHostname]
    :if ([:len $generatedHostname] <= 0) do={ :set generatedHostname [$ipToDashed $leaseActIP] }
    :local generatedFqdn ($generatedHostname . "." . $prefix . "." . $domain)
    :local fqdn ($hostname . "." . $prefix . "." . $domain)

    :if ($fqdn != $generatedFqdn) do={
        :local staleGetUrl ($dnsApiUrl . "/get?token=" . $apiKey . "&domain=" . $generatedFqdn . "&zone=" . $zone . "&listZone=false")
        $logDebug ("A get URL (generated): " . $staleGetUrl)
        :local staleGetBody ""
        :do {
            :local result [/tool fetch url=$staleGetUrl as-value output=user]
            :set staleGetBody ($result->"data")
        } on-error={
            :log warning ($LogPrefix . ": fetch failed for generated A lookup " . $generatedFqdn)
            :set staleGetBody ""
        }
        $logDebug ("A get BODY (generated): " . $staleGetBody)
        :local hasTag false
        :local hasIp false
        :if ([:len $staleGetBody] > 0) do={
            :if ([:find $staleGetBody "\"comments\":\"$DHCPtag\""] != nil) do={ :set hasTag true }
            :if ([:find $staleGetBody "\"ipAddress\":\"$leaseActIP\""] != nil) do={ :set hasIp true }
        }
        :if (($hasTag = true) and ($hasIp = true)) do={
            :log info ($LogPrefix . ": removing stale generated A record " . $generatedFqdn . " -> " . $leaseActIP)
            :local staleAUrl ($dnsApiUrl . "/delete?token=" . $apiKey . "&domain=" . $generatedFqdn . "&zone=" . $zone . "&type=A&value=" . $leaseActIP)
            $logDebug ("A del URL (generated): " . $staleAUrl)
            :local staleABody ""
            :do {
                :local result [/tool fetch url=$staleAUrl as-value output=user]
                :set staleABody ($result->"data")
            } on-error={
                :log warning ($LogPrefix . ": fetch failed for generated A delete " . $generatedFqdn)
                :set staleABody ""
            }
            $logDebug ("A del BODY (generated): " . $staleABody)
        } else={
            $logDebug ("generated A record not deleted for " . $generatedFqdn . ", tag/ip mismatch or record missing")
        }
    }

    :log info ($LogPrefix . ": ensuring A record " . $fqdn . " -> " . $leaseActIP)
    :local addAUrl ($dnsApiUrl . "/add?token=" . $apiKey . "&domain=" . $fqdn . "&zone=" . $zone . "&type=A&ipAddress=" . $leaseActIP . "&overwrite=true&comments=" . $DHCPtag)
    $logDebug ("A add URL: " . $addAUrl)
    :local addABody ""
    :do {
        :local result [/tool fetch url=$addAUrl as-value output=user]
        :set addABody ($result->"data")
    } on-error={
        :log warning ($LogPrefix . ": fetch failed for A add " . $fqdn)
        :set addABody ""
    }
    :log info ($LogPrefix . ": A add BODY: " . $addABody)
    :local addAState "error"
    :if ([:len $addABody] > 0) do={
        :local lower [:convert $addABody transform=lc]
        :if ([:find $lower "\"status\":\"ok\""] != nil) do={ :set addAState "ok" }
        :if (($addAState = "error") and ([:find $lower "already exists"] != nil)) do={ :set addAState "benign" }
    }
    :if ($addAState = "benign") do={ $logDebug ("A add benign for " . $fqdn . " -> " . $leaseActIP) }
    :if ($addAState = "error") do={ :log warning ($LogPrefix . ": A add API non-ok for " . $fqdn . " -> " . $leaseActIP) }

    :log info ($LogPrefix . ": ensuring PTR record " . $reverseFqdn . " -> " . $fqdn)
    :local addPTRUrl ($dnsApiUrl . "/add?token=" . $apiKey . "&domain=" . $reverseFqdn . "&ptrName=" . $fqdn . "&zone=" . $ptrZone . "&type=ptr&overwrite=true&comments=" . $DHCPtag)
    $logDebug ("PTR add URL: " . $addPTRUrl)
    :local addPTRBody ""
    :do {
        :local result [/tool fetch url=$addPTRUrl as-value output=user]
        :set addPTRBody ($result->"data")
    } on-error={
        :log warning ($LogPrefix . ": fetch failed for PTR add " . $fqdn)
        :set addPTRBody ""
    }
    :log info ($LogPrefix . ": PTR add BODY: " . $addPTRBody)
    :local addPTRState "error"
    :if ([:len $addPTRBody] > 0) do={
        :local lower [:convert $addPTRBody transform=lc]
        :if ([:find $lower "\"status\":\"ok\""] != nil) do={ :set addPTRState "ok" }
        :if (($addPTRState = "error") and ([:find $lower "already exists"] != nil)) do={ :set addPTRState "benign" }
    }
    :if ($addPTRState = "benign") do={ $logDebug ("PTR add benign for " . $reverseFqdn . " -> " . $fqdn) }
    :if ($addPTRState = "error") do={ :log warning ($LogPrefix . ": PTR add API non-ok for " . $reverseFqdn . " -> " . $fqdn) }

    :log info ($LogPrefix . ": DNS sync finished")
} else={
    :local eventHostnameRaw $"lease-hostname"
    :local eventHostname [$trimString $eventHostnameRaw]
    :set eventHostname [$sanitizeHostname $eventHostname]
    :delay $unbindDelay
    /ip dhcp-server lease
    :local reboundLeaseId [find where address=$leaseActIP and status="bound" and active-address=$leaseActIP and active-server=$leaseServerName]
    :if ([:len $reboundLeaseId] > 0) do={
        :log info ($LogPrefix . ": skipping cleanup for " . $leaseActIP . ", lease is already bound again")
    } else={
    :local leaseId [find where address=$leaseActIP]
    :local hostname ""
    :local isFallback false

    :if ([:len $eventHostname] > 0) do={
        :set hostname $eventHostname
    }

    :if (([:len $hostname] <= 0) and ($leaseId != "")) do={
        :local hostnameRaw [get $leaseId host-name]
        :set hostname [$trimString $hostnameRaw]
        :set hostname [$sanitizeHostname $hostname]
    }

    :if (([:len $hostname] <= 0) and ($leaseId != "")) do={
        :set hostname [$ipToDashed $leaseActIP]
        :set hostname [$sanitizeHostname $hostname]
        :if ([:len $hostname] <= 0) do={ :set hostname [$ipToDashed $leaseActIP] }
        :set isFallback true
    }

    :if ([:len $hostname] <= 0) do={
        :log warning ($LogPrefix . ": skipping cleanup for " . $leaseActIP . ", hostname is unavailable after unbind")
    } else={

    :local targetFqdn ($hostname . "." . $prefix . "." . $domain)

           :if ($isFallback = true) do={
               :log warning ($LogPrefix . ": No lease found for " . $leaseActIP . ", doing fallback cleanup for " . $targetFqdn)
           }

           :log info ($LogPrefix . ": removing A record " . $targetFqdn . " -> " . $leaseActIP)
           :local delAUrl ($dnsApiUrl . "/delete?token=" . $apiKey . "&domain=" . $targetFqdn . "&zone=" . $zone . "&type=A&value=" . $leaseActIP)
           $logDebug ("A del URL: " . $delAUrl)
           :local delABody ""
           :do {
               :local result [/tool fetch url=$delAUrl as-value output=user]
               :set delABody ($result->"data")
           } on-error={
               :log warning ($LogPrefix . ": fetch failed for A delete " . $targetFqdn)
               :set delABody ""
           }
           $logDebug ("A del BODY: " . $delABody)
           :local delAState "error"
           :if ([:len $delABody] > 0) do={
               :local lower [:convert $delABody transform=lc]
               :if ([:find $lower "\"status\":\"ok\""] != nil) do={ :set delAState "ok" }
               :if (($delAState = "error") and ([:find $lower "not found"] != nil)) do={ :set delAState "benign" }
           }
           :if ($delAState = "benign") do={ $logDebug ("A delete benign for " . $targetFqdn . " -> " . $leaseActIP) }
           :if ($delAState = "error") do={ :log warning ($LogPrefix . ": A delete API non-ok for " . $targetFqdn . " -> " . $leaseActIP) }
           :log info ($LogPrefix . ": removed A record " . $targetFqdn . " -> " . $leaseActIP)

           :log info ($LogPrefix . ": removing PTR record " . $reverseFqdn . " -> " . $targetFqdn)
           :local delPTRUrl ($dnsApiUrl . "/delete?token=" . $apiKey . "&domain=" . $reverseFqdn . "&ptrName=" . $targetFqdn . "&zone=" . $ptrZone . "&type=ptr")
           $logDebug ("PTR del URL: " . $delPTRUrl)
           :local delPTRBody ""
           :do {
               :local result [/tool fetch url=$delPTRUrl as-value output=user]
               :set delPTRBody ($result->"data")
           } on-error={
               :log warning ($LogPrefix . ": fetch failed for PTR delete " . $targetFqdn)
               :set delPTRBody ""
           }
           $logDebug ("PTR del BODY: " . $delPTRBody)
           :local delPTRState "error"
           :if ([:len $delPTRBody] > 0) do={
               :local lower [:convert $delPTRBody transform=lc]
               :if ([:find $lower "\"status\":\"ok\""] != nil) do={ :set delPTRState "ok" }
               :if (($delPTRState = "error") and ([:find $lower "not found"] != nil)) do={ :set delPTRState "benign" }
           }
           :if ($delPTRState = "benign") do={ $logDebug ("PTR delete benign for " . $reverseFqdn . " -> " . $targetFqdn) }
           :if ($delPTRState = "error") do={ :log warning ($LogPrefix . ": PTR delete API non-ok for " . $reverseFqdn . " -> " . $targetFqdn) }

    :if ($isFallback = true) do={
        :log info ($LogPrefix . ": cleanup finished (fallback)")
    } else={
        :log info ($LogPrefix . ": cleanup finished")
    }
    }
    }
}
