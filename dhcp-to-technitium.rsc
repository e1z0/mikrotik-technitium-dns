# (c) 2024 e1z0
:local DHCPtag   "#LAB01#DHCP2DNS#";                           # Used in dns record comments
:local LogPrefix "DHCP2DNS ($leaseServerName)";                # used in router logging
:local domain "lab01.domain.local";                            # Domain name or domain name with prefix
:local dnsApiUrl "https://technitium.local/api/zones/records"; # Technitium master server api endpoint
:local apiKey "API_KEY";                                       # API Key from Technitium DNS
:local zone "domain.local";                                    # DNS Zone name in technitium DNS
:local ptrzone "168.192.in-addr.arpa";                         # PTR Zone name in technitium DNS

###
# Functions

# Define the function to reverse an IP address
:local reverseIPAddressShort do={
    :local ipAddress $1

    # Find positions of the dots
    :local firstDot [:find $ipAddress "."]
    :local secondDot [:find $ipAddress "." ($firstDot + 1)]
    :local thirdDot [:find $ipAddress "." ($secondDot + 1)]

    # Extract each octet
    :local octet1 [:pick $ipAddress 0 $firstDot]
    :local octet2 [:pick $ipAddress ($firstDot + 1) $secondDot]
    :local octet3 [:pick $ipAddress ($secondDot + 1) $thirdDot]
    :local octet4 [:pick $ipAddress ($thirdDot + 1) [:len $ipAddress]]

    # Concatenate the reversed IP
    :return "$octet4.$octet3"
}

# remove \0 and spaces from string passed as inStr=<string>
:local trimString do=\
{
  :local outStr
  :for i from=0 to=([:len $inStr] - 1) do=\
  {
    :local tmp [:pick $inStr $i];
    :if (($tmp !=" ") and ($tmp !="\00")) do=\
    {
      :set outStr ($outStr . $tmp)
    }
  }
  :return $outStr
}

# "a.b.c.d" -> "a-b-c-d" for IP addresses used as replacement for missing host names
:local ip2Host do=\
{
  :local outStr
  :for i from=0 to=([:len $inStr] - 1) do=\
  {
    :local tmp [:pick $inStr $i];
    :if ($tmp =".") do=\
    {
      :set tmp "-"
    }
    :set outStr ($outStr . $tmp)
  }
  :return $outStr
}

###
# Script entry point
#

:log info "$LogPrefix: Script is starting"

:if ( [ :len $leaseActIP ] <= 0 ) do=\
{
  :log error "$LogPrefix: empty lease address"
  :error "empty lease address"
}

:if ( $leaseBound = 1 ) do=\
{
  # new DHCP lease added
  
  /ip dhcp-server
  :local ttl [ get [ find name=$leaseServerName ] lease-time ]
  network 
  .. lease
  :local leaseId [ find address=$leaseActIP ]

  # Check for multiple active leases for the same IP address. It's weird and it shouldn't be, but just in case.
  :if ( [ :len $leaseId ] != 1) do=\
  {
    :log warning "$LogPrefix: Multiple active DHCP leases for '$leaseActIP' (???)"
    :error "Multiple active DHCP leases for '$leaseActIP' (???)"
  }  
  :local hostname [ get $leaseId host-name ]
  :set hostname [ $trimString inStr=$hostname ]

  :if ( [ :len $hostname ] <= 0 ) do=\
  {
    :set hostname [ $ip2Host inStr=$leaseActIP ]
    :log info "$LogPrefix: Empty hostname for '$leaseActIP', using generated host name '$hostname'"
  }
  :if ( [ :len $domain ] <= 0 ) do=\
  {
    :log warning "$LogPrefix: Empty domainname for '$leaseActIP', cannot create static DNS name"
    :error "Empty domainname for '$leaseActIP'"
  }
  :local fqdn ($hostname . "." .  $domain)
  :log info "$LogPrefix: Adding dns name: $fqdn for $leaseActIP"
  :local url "$dnsApiUrl/add?token=$apiKey&domain=$fqdn&zone=$zone&type=A&ipAddress=$leaseActIP&comments=$DHCPtag"
  :local result [/tool fetch url=$url as-value output=user]
  :local content ($result->"data")
  :local parsedData [:parse $content]
  :log info "$LogPrefix: Raw JSON: $content"

  :log info "$LogPrefix: A Record added"
  # ptr record
  :local reverse [$reverseIPAddressShort $leaseActIP]
  :log info "$LogPrefix: Adding reverse dns name: $fqdn for $reverse"
  :local url "$dnsApiUrl/add?token=$apiKey&domain=$reverse.$ptrzone&ptrName=$fqdn&zone=$ptrzone&type=ptr&comments=$DHCPtag"
  :local result [/tool fetch url=$url as-value output=user]
  :local content ($result->"data")
  :local parsedData [:parse $content]
  :log info "$LogPrefix: Raw JSON: $content"
  :log info "$LogPrefix: PTR Record added"
}\
else=\
{
  # DHCP lease removed
:local leaseID [/ip dhcp-server lease find where address=$leaseActIP]
# Check if a lease ID was found
:if ($leaseID != "") do={
    #:log info "Lease ID for IP $leaseActIP is $leaseID"
    /ip dhcp-server lease
    :local leaseId [ find address=$leaseActIP ]
    :local hostname [ get $leaseId host-name ]
    :set hostname [ $trimString inStr=$hostname ]
    :if ( [ :len $hostname ] <= 0 ) do=\
    {
       :set hostname [ $ip2Host inStr=$leaseActIP ]
    }
    :local fqdn ($hostname . "." . $domain)
    :log info "$LogPrefix: Removing dns name: $fqdn for $leaseActIP"
    :local url "$dnsApiUrl/delete?token=$apiKey&domain=$fqdn&zone=$zone&type=A&value=$leaseActIP"
    :local result [/tool fetch url=$url as-value output=user]
    :local content ($result->"data")
    :local parsedData [:parse $content]
    :log info "$LogPrefix: DEBUG - Raw JSON: $content"
    :log info "$LogPrefix: DNS: '$fqdn' for '$leaseActIP' is removed"
    :local reverse [$reverseIPAddressShort $leaseActIP]
    :log info "$LogPrefix: Removing reverse dns name: $fqdn for $reverse"
    :local url "$dnsApiUrl/delete?token=$apiKey&domain=$reverse.$ptrzone&ptrName=$fqdn&zone=$ptrzone&type=ptr"
    :local result [/tool fetch url=$url as-value output=user]
    :local content ($result->"data")
    :local parsedData [:parse $content]
    :log info "$LogPrefix: Raw JSON: $content"

    :log info "$LogPrefix: PTR Record removed"
} else={
    :log info "$LogPrefix: No lease found for IP $leaseActIP, cannot remove dns"
}
}
:log info "$LogPrefix: Script finished"
