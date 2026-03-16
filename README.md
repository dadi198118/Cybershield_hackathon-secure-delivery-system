## Cybershield_hackathon-secure-delivery-system
Deception-Driven Secure Data Architecture for Citizen Information Systems using decoy database and intrusion detection using honey pots


A cybersecurity prototype that demonstrates how deception security can protect sensitive citizen databases by misleading attackers into interacting with a decoy (honeypot) database while the real data remains protected.

The system detects suspicious activity, logs attacks, and visualizes threats in a Security Operations Center dashboard.

# Project Overview

Traditional database security focuses only on defense (firewalls, encryption, authentication). However, once an attacker bypasses those defenses, they can often access sensitive information undetected.
This project introduces a deception-based defense architecture where suspicious users are redirected to a fake but realistic database, allowing the system to Protect real citizen data,Monitor attacker behavior,
Detect malicious activity and Visualize attacks in real time

Key Features

* Security Gateway that analyzes every request
* Real database containing legitimate citizen data
* Decoy database (honeypot) containing fake citizen data
* Honey tokens that trigger alerts when accessed
* Automatic routing of suspicious users to the decoy database
* Attack logging and monitoring
* Dashboard for real-time monitoring

