This PowerShell module allows system administrators to retreive and display information about a remote computer.  The remote computer must be reachable on the network and must have RPC and WMI allowed and enabled.  If you use Active Directory and have RSAT installed, you can also retreive information about the last person to use the computer.  

Syntax: get-systeminfo `<name`> or get-systeminfo `<ipaddress`>

Information Displayed  
Name  
Model  
Serial  
OS  
Product Key  
Processor Cores  
Bitlocker Status  
Bitlocker Percent  
TPM Version  
System Restore  
Last User  
Location  
Department  
Phone  
Email  
Mac Addresses  
Network Printers  
