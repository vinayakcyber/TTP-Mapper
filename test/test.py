import matplotlib.pyplot as plt
import pandas as pd

# Provided list of sections and techniques
sections = [
    'Time Based Evasion', 'T1053', 'Code Signing', 'T1566.002', 'Proxy', 'T1059.001', 'T1055', 'T1082', 'Weaken Encryption',
    'Web Service', 'T1059', 'T1076', 'Symmetric Cryptography', 'Web Service', 'T1571', 'T1547', 'T1070', 'T1566',
    'Regsvr32', 'T1489', 'T1059.005', 'T1059', 'Gather Victim Identity Information', 'Spearphishing via Service',
    'Code Signing', 'T1568.002', 'T1497.001', 'T1027', 'T1059.001', 'T1057', 'T1547.001', 'T1110', 'T1176', 'T1574',
    'User Activity Based Checks', 'Use Alternate Authentication Material', 'Botnet', 'T1547.001', 'T1573',
    'Establish Accounts', 'T1574', 'T1082', 'T1053', 'T1190', 'T1059', 'T1055.012', 'T1112', 'Time Based Evasion'
]

# Sample mapping (this would normally come from a more extensive mapping of techniques to categories)
technique_mapping = {
    'T1053': 'Scheduled Task/Job',
    'T1566.002': 'Phishing: Spearphishing Link',
    'T1059.001': 'Command and Scripting Interpreter: PowerShell',
    'T1055': 'Process Injection',
    'T1082': 'System Information Discovery',
    'T1059': 'Command and Scripting Interpreter',
    'T1076': 'Remote Desktop Protocol',
    'T1571': 'Non-Application Layer Protocol',
    'T1547': 'Boot or Logon Autostart Execution',
    'T1070': 'Indicator Removal on Host',
    'T1566': 'Phishing',
    'T1489': 'Service Stop',
    'T1059.005': 'Command and Scripting Interpreter: Visual Basic',
    'T1057': 'Process Discovery',
    'T1547.001': 'Registry Run Keys / Startup Folder',
    'T1110': 'Brute Force',
    'T1176': 'Browser Extensions',
    'T1574': 'Hijack Execution Flow',
    'T1573': 'Encrypted Channel',
    'T1190': 'Exploit Public-Facing Application',
    'T1055.012': 'Process Hollowing',
    'T1112': 'Modify Registry',
    'T1027': 'Obfuscated Files or Information',
    'T1497.001': 'Virtualization/Sandbox Evasion: System Checks',
    'T1568.002': 'Dynamic Resolution: Domain Generation Algorithms',
    # Add additional mappings as needed
}

# Fill missing mappings with their own names
for item in sections:
    if item not in technique_mapping:
        technique_mapping[item] = item

# Count occurrences of each category
category_counts = {}
for section in sections:
    category = technique_mapping.get(section, section)
    category_counts[category] = category_counts.get(category, 0) + 1

# Convert to DataFrame
df = pd.DataFrame(list(category_counts.items()), columns=['Technique', 'Count'])

# Plot the data
plt.figure(figsize=(12, 8))
plt.barh(df['Technique'], df['Count'], color='skyblue')
plt.xlabel('Count')
plt.ylabel('Technique')
plt.title('MITRE ATT&CK Techniques Frequency')
plt.tight_layout()

# Save the plot as a JPG file
plt.savefig('mitre_attack_chart.jpg', format='jpg')

# Show the plot
plt.show()
