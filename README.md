# Info

[Read the article](https://e1z0.net/articles/miktotik-technitium)

# How to use

In Mikrotik navigate **System > Scripts > +**

Paste the script from file **dhcp-to-technitium.rsc**, Add **Read, Write and Test** policies, name it "dhcp-to-technitium" and then click OK.

Now to assign it to DHCP Server navigate IP > DHCP Server > DHCP > Your DHCP Instance > Script write "dhcp-to-technitium" (Without quotes), click OK.
