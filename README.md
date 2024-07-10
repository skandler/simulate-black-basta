# Blackbasta Ransomware Atomic Simulation
# Author : Sebastian Kandler (@skandler)
# Date : 02/07/2024
# Simulate Blackbasta Ransomware tactics, techniques, and procedures (TTP) with atomic red team and some own tests to validate security controls
#
# Recommend to run it also without pattern based malware protection, to verify EDR behaviour based detections, otherwise pattern based AV will block most of the tools. An attacker who does obfuscation of these attack tools, wont be detected by pattern based av.
# Expect that attackers will turn off your EDR Solution like in steps 22-24, how do you detect and protect without EDR? running it without EDR will also test your system hardening settings like Windows Credential Dump Hardening settings like LSA Protect or Credential guard. 
#
# Prerequisite: https://github.com/redcanaryco/invoke-atomicredteam - works best with powershell 7
#
# see Story about this topic at Medium: https://medium.com/@sebastian.kandler/battle-test-your-security-simulating-black-basta-ransomware-attacks-1591dd6a44bc
#
# see detailled descriptions of tests at github readme files for atomics for example for T1003: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
#
# References
# 
# https://www.picussecurity.com/resource/blog/black-basta-ransomware-analysis-cisa-alert-aa24-131a
# https://www.threatdown.com/blog/black-basta-ransomware-exploits-windows-error-reporting-service-vulnerability/
# https://www.ic3.gov/Media/News/2024/240511.pdf
# https://www.kroll.com/en/insights/publications/cyber/black-basta-technical-analysis
# https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/
# https://atomicredteam.io/defense-evasion/T1564/
# https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
