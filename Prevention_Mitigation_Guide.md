# GhostLocker Prevention & Mitigation Guide
## Protecting Your EDR from AppLocker-Based Attacks

**Document Version:** 1.0  
**Last Updated:** December 27, 2025  
**Author:** CyberScroll  
**Audience:** Security Administrators, SOC Teams, Blue Team

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Prevention Strategies](#prevention-strategies)
3. [Detection Mechanisms](#detection-mechanisms)
4. [Incident Response Playbook](#incident-response-playbook)
5. [Configuration Hardening](#configuration-hardening)
6. [Monitoring Requirements](#monitoring-requirements)
7. [Testing & Validation](#testing-validation)

---

## Executive Summary

GhostLocker demonstrates how Windows AppLocker can be weaponized to disable EDR solutions by creating deny rules that prevent critical security processes from starting. This document provides comprehensive prevention and mitigation strategies.

**Key Facts:**
- **Requires:** Local Administrator privileges
- **Target:** Microsoft Defender for Endpoint (MDE) and other EDR solutions
- **Method:** AppLocker FilePathRule with Action="Deny"
- **Impact:** Complete EDR disable after system reboot
- **Detection Difficulty:** Medium (multiple detection points available)

---

## Prevention Strategies

### 1. Privileged Access Management (MOST EFFECTIVE)

**Objective:** Prevent attackers from obtaining local admin rights

#### Implementation Steps:

**A. Remove Local Admin Rights**
```powershell
# Audit current local administrators
Get-LocalGroupMember -Group "Administrators" | Format-Table

# Remove unnecessary accounts
Remove-LocalGroupMember -Group "Administrators" -Member "Domain\Username"

# Deploy via Group Policy to all endpoints
# Computer Configuration > Preferences > Control Panel Settings > Local Users and Groups
```

**B. Implement Just-In-Time (JIT) Admin Access**
```powershell
# Use Microsoft Entra ID Privileged Identity Management (PIM)
# Or deploy LAPS (Local Administrator Password Solution)

# LAPS PowerShell deployment:
Import-Module AdmPwd.PS
Update-AdmPwdADSchema
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=domain,DC=com"
```

**C. Conditional Access Policies**
- Require MFA for admin elevation
- Limit admin access to specific devices
- Enforce geographic restrictions
- Time-based access windows

**Expected Outcome:** 90%+ reduction in attack surface


### 2. AppLocker Policy Protection (HIGHLY EFFECTIVE)

**Objective:** Prevent unauthorized modifications to AppLocker policies

#### Method A: Windows Defender Application Control (WDAC)

Create a WDAC policy that protects AppLocker configuration:

```powershell
# Step 1: Create base policy
New-CIPolicy -Level FilePublisher -FilePath "C:\Temp\BasePolicy.xml" -UserPEs

# Step 2: Add protection rules for policy files
$rulesToAdd = @(
    "C:\Windows\System32\AppLocker\*.xml",
    "C:\Windows\System32\GroupPolicy\Machine\Registry.pol",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
)

# Step 3: Convert to binary format
ConvertFrom-CIPolicy -XmlFilePath "C:\Temp\BasePolicy.xml" -BinaryFilePath "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"

# Step 4: Enable WDAC
Restart-Computer
```

#### Method B: Scheduled Task Monitoring

```powershell
# Create scheduled task that reverts unauthorized changes
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-File "C:\Scripts\Revert-AppLockerChanges.ps1"'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Protect-AppLockerPolicy" -Action $action -Trigger $trigger -Principal $principal
```

**Expected Outcome:** 80% reduction in successful policy tampering


### 3. Tamper Protection Enhancement (MODERATELY EFFECTIVE)

**Objective:** Leverage built-in Defender self-protection

#### Configuration:

```powershell
# Enable Tamper Protection via Registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 5 -Type DWord

# Verify status
Get-MpComputerStatus | Select-Object IsTamperProtected

# Force update definitions
Update-MpSignature
```

#### Intune/Group Policy Configuration:
```
Path: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Features
Setting: Prevent users from modifying settings
Value: Enabled

Path: Microsoft Defender Security Center > Virus and threat protection
Setting: Tamper Protection
Value: Enabled
```

**Limitations:** Tamper Protection focuses on service/registry tampering, not AppLocker policy changes

**Expected Outcome:** 50% reduction (effectiveness varies by Windows version)


### 4. Registry Access Control Lists (EFFECTIVE)

**Objective:** Restrict write access to AppLocker registry keys

```powershell
# Backup current ACL
$aclBackup = Get-Acl -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
$aclBackup | Export-Clixml -Path "C:\Backup\SrpV2_ACL.xml"

# Create restrictive ACL
$acl = Get-Acl -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

# Remove all inherited permissions
$acl.SetAccessRuleProtection($true, $false)

# Grant SYSTEM full control only
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    "NT AUTHORITY\SYSTEM",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.AddAccessRule($rule)

# Apply ACL
Set-Acl -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -AclObject $acl
```

**Warning:** Test thoroughly before production deployment

**Expected Outcome:** 70% reduction in direct registry manipulation


### 5. File System Monitoring (MODERATELY EFFECTIVE)

**Objective:** Detect and alert on AppLocker policy file changes

```powershell
# Create File System Watcher
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\Windows\System32\GroupPolicy\Machine\"
$watcher.Filter = "*.pol"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

# Define action on change
$action = {
    $path = $Event.SourceEventArgs.FullPath
    $changeType = $Event.SourceEventArgs.ChangeType
    
    Write-EventLog -LogName "Security" -Source "AppLockerMonitor" -EventId 9001 `
        -EntryType Warning -Message "AppLocker policy file modified: $path ($changeType)"
    
    # Optional: Send alert to SIEM
    # Send-SIEMAlert -EventType "PolicyChange" -FilePath $path
}

Register-ObjectEvent -InputObject $watcher -EventName Changed -Action $action
```

**Expected Outcome:** Real-time alerting, 60% faster incident response


### 6. Service Configuration Protection (EFFECTIVE)

**Objective:** Prevent unauthorized AppID service changes

```powershell
# Disable AppID services by default (if not using AppLocker)
Set-Service -Name AppID -StartupType Disabled
Set-Service -Name AppIDSvc -StartupType Disabled

# OR if using AppLocker, monitor for changes:
$serviceMonitor = @'
$services = @("AppID", "AppIDSvc")
foreach ($svc in $services) {
    $config = Get-Service $svc | Select-Object StartType
    if ($config.StartType -eq "Automatic") {
        Write-EventLog -LogName "Security" -Source "ServiceMonitor" -EventId 9002 `
            -EntryType Warning -Message "AppID service $svc set to Automatic startup"
    }
}
'@

# Deploy as scheduled task (runs every 5 minutes)
```

**Expected Outcome:** 75% reduction in service-based attacks


### 7. Network Segmentation (MODERATELY EFFECTIVE)

**Objective:** Limit lateral movement after compromise

#### Implementation:

1. **EDR Management Network Isolation**
   - Separate VLAN for EDR management traffic
   - Firewall rules restricting admin access
   - Jump server/bastion host requirement

2. **Workstation Segmentation**
   ```
   Zone 1: Standard Users (No admin rights)
   Zone 2: Power Users (JIT admin access only)
   Zone 3: Admin Workstations (Fully monitored)
   ```

3. **Micro-segmentation Rules**
   ```powershell
   # Block lateral movement using Windows Firewall
   New-NetFirewallRule -DisplayName "Block Admin Shares" -Direction Inbound `
       -Action Block -Protocol TCP -LocalPort 445 -RemoteAddress LocalSubnet
   ```

**Expected Outcome:** Limits blast radius, 40% reduction in widespread compromise


### 8. EDR Health Monitoring (CRITICAL FOR DETECTION)

**Objective:** Rapid detection of EDR failure/disable

#### Monitoring Dashboard Requirements:

**A. Real-time Metrics**
```kusto
// Create dashboard showing device health
DeviceInfo
| where Timestamp > ago(5m)
| summarize 
    HealthyDevices = countif(OnboardingStatus == "Onboarded"),
    UnhealthyDevices = countif(OnboardingStatus != "Onboarded"),
    NoTelemetryDevices = countif(LastSeenTimestamp < ago(10m))
| extend HealthPercentage = (HealthyDevices * 100.0) / (HealthyDevices + UnhealthyDevices)
```

**B. Alerting Rules**
```kusto
// Alert if device stops sending telemetry
DeviceInfo
| where OnboardingStatus == "Onboarded"
| where LastSeenTimestamp < ago(15m)
| summarize NoTelemetryDuration = datetime_diff('minute', now(), max(LastSeenTimestamp)) by DeviceName
| where NoTelemetryDuration > 15
| extend Severity = case(
    NoTelemetryDuration > 60, "Critical",
    NoTelemetryDuration > 30, "High",
    "Medium"
)
```

**C. Service Status Monitoring**
```powershell
# Deploy to all endpoints via Group Policy startup script
$defenderServices = @("Sense", "WinDefend", "WdNisSvc", "SecurityHealthService")
$failed = @()

foreach ($svc in $defenderServices) {
    $status = Get-Service $svc -ErrorAction SilentlyContinue
    if ($status.Status -ne "Running") {
        $failed += $svc
    }
}

if ($failed.Count -gt 0) {
    # Report to management server
    Invoke-RestMethod -Uri "https://monitoring.company.com/api/alert" -Method POST `
        -Body (@{
            DeviceName = $env:COMPUTERNAME
            FailedServices = $failed -join ","
            Timestamp = Get-Date
        } | ConvertTo-Json)
}
```

**Expected Outcome:** Detection within 5-15 minutes of EDR disable


### 9. Baseline Configuration Validation (EFFECTIVE)

**Objective:** Ensure consistent security posture across fleet

```powershell
# Create baseline configuration
$baseline = @{
    AppIDServiceStatus = "Disabled"  # Unless using AppLocker
    AppLockerPolicyExists = $false   # Unless intentionally configured
    LocalAdmins = @("Domain Admins", "SYSTEM")
    TamperProtection = $true
    DefenderServicesRunning = $true
}

# Validation script (deploy via Intune/SCCM)
function Test-SecurityBaseline {
    param($Baseline)
    
    $issues = @()
    
    # Check AppID service
    $appid = Get-Service AppID
    if ($appid.StartType -ne $Baseline.AppIDServiceStatus) {
        $issues += "AppID service configuration mismatch"
    }
    
    # Check local admins
    $admins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
    $unexpected = $admins | Where-Object { $_ -notin $Baseline.LocalAdmins }
    if ($unexpected) {
        $issues += "Unexpected local admins: $($unexpected -join ', ')"
    }
    
    # Check AppLocker policies
    $policies = Get-AppLockerPolicy -Effective
    if ($policies -and -not $Baseline.AppLockerPolicyExists) {
        $issues += "Unexpected AppLocker policies detected"
    }
    
    return $issues
}

# Report findings
$results = Test-SecurityBaseline -Baseline $baseline
if ($results) {
    # Send to SIEM/SOC
    Write-EventLog -LogName "Security" -Source "BaselineCheck" -EventId 9003 `
        -EntryType Warning -Message ($results -join "`n")
}
```

**Expected Outcome:** Automated compliance checking, 50% faster deviation detection


### 10. Security Awareness Training (FOUNDATIONAL)

**Objective:** Reduce likelihood of initial compromise

#### Training Topics:

1. **Phishing Recognition**
   - Credential harvesting techniques
   - Malicious attachments/links
   - Social engineering tactics

2. **Privilege Management**
   - Why admin rights are dangerous
   - Proper use of JIT access
   - Reporting suspicious elevation requests

3. **Incident Reporting**
   - Signs of compromise
   - How to report security concerns
   - Contact information for SOC

#### Metrics:
- Phishing simulation click rate: Target <5%
- Security incident reporting: Target >80% awareness
- Training completion: 100% quarterly

**Expected Outcome:** 60% reduction in successful phishing attacks

---

## Detection Mechanisms

### Primary Detection Signals

| Signal | Detection Method | Confidence Level | Response Time |
|--------|------------------|------------------|---------------|
| AppLocker policy changes | MDE Query #1, #4 | High | Real-time |
| AppID service enablement | MDE Query #2 | Medium | Real-time |
| Defender process blocking | MDE Query #3 | Critical | Real-time |
| Registry modifications | MDE Query #4 | High | Real-time |
| Service failures | MDE Query #6 | High | 5 minutes |
| Full attack chain | MDE Query #7 | Very High | Hourly |
| Encoded PowerShell | MDE Query #8 | Medium | Daily |
| Event log analysis | MDE Query #5 | Medium | 15 minutes |

### Secondary Detection Signals

1. **Windows Event Logs**
   - Event ID 8004: AppLocker block event
   - Event ID 7036: Service state change
   - Event ID 7040: Service startup type change
   - Event ID 4719: System audit policy change

2. **Performance Counters**
   ```powershell
   # Monitor AppLocker enforcement overhead
   Get-Counter "\AppLocker\Evaluations per second"
   Get-Counter "\AppLocker\Policy load time (ms)"
   ```

3. **File Integrity Monitoring**
   - Monitor: `C:\Windows\System32\GroupPolicy\Machine\Registry.pol`
   - Monitor: `C:\Windows\System32\AppLocker\*.xml`

---

## Incident Response Playbook

### Phase 1: Detection & Triage (0-15 minutes)

**Alert Trigger:** Defender process blocking detected OR AppLocker policy change

#### Immediate Actions:

1. **Validate Alert**
   ```kusto
   // Run MDE Query #7 for affected device
   DeviceEvents
   | where DeviceName == "AFFECTED-DEVICE"
   | where Timestamp > ago(24h)
   | where ActionType in ("ProcessBlocked", "RegistryValueSet")
   | project Timestamp, ActionType, FileName, ProcessCommandLine
   ```

2. **Check Device Status**
   - MDE Portal: Device health status
   - Last telemetry received timestamp
   - Active logged-on users

3. **Assess Scope**
   ```kusto
   // Check if attack is widespread
   DeviceEvents
   | where Timestamp > ago(1h)
   | where ActionType == "ProcessBlocked"
   | where FileName has_any ("MsSense.exe", "MsMpEng.exe")
   | summarize AffectedDevices = dcount(DeviceName)
   ```

**Decision Point:** 
- Single device → Proceed to Phase 2
- Multiple devices → Escalate to Incident Commander, initiate organization-wide response

### Phase 2: Containment (15-30 minutes)

#### Immediate Containment:

1. **Network Isolation**
   ```powershell
   # Via MDE Live Response or SCCM
   New-NetFirewallRule -DisplayName "Emergency Isolation" -Direction Outbound `
       -Action Block -RemoteAddress Any
   ```

2. **Collect Forensic Artifacts**
   ```powershell
   # MDE Live Response commands:
   run GetAppLockerPolicy.txt Get-AppLockerPolicy -Effective -Xml
   run GetServices.txt Get-Service AppID,AppIDSvc,Sense,WinDefend
   run GetLocalAdmins.txt Get-LocalGroupMember -Group Administrators
   run GetRegistry.txt Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Recurse
   ```

3. **Preserve Evidence**
   - Export AppLocker XML policy
   - Capture memory dump (if available)
   - Save Windows Event Logs (Security, System, AppLocker)

### Phase 3: Eradication (30-60 minutes)

#### Removal Steps:

1. **Run Cleanup Script**
   ```powershell
   # Deploy Complete_Cleanup.ps1 from GhostLocker toolkit
   # Or manual removal:
   
   # Remove AppLocker policies
   $policy = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy
   Set-AppLockerPolicy -PolicyObject $policy
   
   # Clear registry
   Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Recurse -Force
   Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer" -Recurse -Force
   Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Srp" -Recurse -Force -ErrorAction SilentlyContinue
   
   # Reset Group Policy
   Remove-Item "C:\Windows\System32\GroupPolicy" -Recurse -Force
   gpupdate /force
   
   # Disable AppID services
   Set-Service AppID -StartupType Disabled
   Set-Service AppIDSvc -StartupType Disabled
   ```

2. **Force Reboot**
   ```powershell
   Restart-Computer -Force
   ```

3. **Verify Restoration**
   ```powershell
   # After reboot, verify Defender processes
   Get-Process | Where-Object { $_.Name -match "MsSense|MsMpEng|NisSrv|Sense" }
   
   # Verify service status
   Get-Service Sense,WinDefend,WdNisSvc | Format-Table Name,Status,StartType
   ```

### Phase 4: Recovery (1-2 hours)

1. **Re-onboard to MDE** (if necessary)
   ```powershell
   # Re-run onboarding script from MDE portal
   # Verify connectivity
   Test-NetConnection -ComputerName "events.data.microsoft.com" -Port 443
   ```

2. **Validate EDR Functionality**
   - Check MDE portal for telemetry
   - Run test detection (EICAR or benign IOC)
   - Verify behavioral detections active

3. **Restore Normal Operations**
   - Remove network isolation
   - Notify user
   - Document incident

### Phase 5: Post-Incident (24-48 hours)

#### Forensic Analysis:

1. **Determine Initial Access Vector**
   - Review authentication logs
   - Analyze phishing email headers
   - Check vulnerability scan results
   - Investigate credential compromise indicators

2. **Timeline Reconstruction**
   ```kusto
   // Full attack timeline
   union DeviceProcessEvents, DeviceRegistryEvents, DeviceEvents
   | where DeviceName == "AFFECTED-DEVICE"
   | where Timestamp between (datetime(2025-12-27 10:00) .. datetime(2025-12-27 11:00))
   | project Timestamp, ActionType, ProcessCommandLine, RegistryKey, FileName
   | order by Timestamp asc
   ```

3. **Identify Persistence Mechanisms**
   - Check scheduled tasks
   - Review startup items
   - Analyze registry run keys
   - Investigate WMI subscriptions

#### Lessons Learned:

1. **Root Cause Analysis**
   - How did attacker gain admin rights?
   - What controls failed?
   - What worked well in detection/response?

2. **Remediation Recommendations**
   - Implement missing preventive controls
   - Tune detection rules to reduce false positives
   - Update runbooks based on lessons learned

3. **Communication**
   - Executive summary for leadership
   - Technical report for engineering teams
   - User awareness communication (if widespread)

---

## Configuration Hardening

### MDE-Specific Hardening

```powershell
# 1. Enable all Defender features
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableBlockAtFirstSeen $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisablePrivacyMode $false
Set-MpPreference -DisableScanningNetworkFiles $false
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false

# 2. Enable cloud-delivered protection
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# 3. Configure attack surface reduction rules
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 `
    -AttackSurfaceReductionRules_Actions Enabled  # Block executable content from email

Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A `
    -AttackSurfaceReductionRules_Actions Enabled  # Block Office from creating child processes

# 4. Enable controlled folder access (if applicable)
Set-MpPreference -EnableControlledFolderAccess Enabled
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\TrustedApp\app.exe"
```

### Group Policy Hardening

```
Computer Configuration > Policies > Administrative Templates > Windows Components:

1. Microsoft Defender Antivirus > Real-time Protection
   ✓ Turn on behavior monitoring: Enabled
   ✓ Turn on process scanning: Enabled
   
2. Microsoft Defender Antivirus > MAPS
   ✓ Join Microsoft MAPS: Advanced MAPS
   ✓ Send file samples: Send all samples
   
3. Microsoft Defender Antivirus > Tamper Protection
   ✓ Configure tamper protection: Enabled
   
4. Windows PowerShell
   ✓ Turn on PowerShell Script Block Logging: Enabled
   ✓ Turn on PowerShell Transcription: Enabled
   
5. AppLocker (if used for legitimate purposes)
   ✓ Configure policy enforcement: Enforce rules
   ✓ Display custom URL: https://security.company.com/applocker-denied
```

### Registry Hardening

```powershell
# Protect Defender registry keys
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows Defender",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
)

foreach ($path in $registryPaths) {
    $acl = Get-Acl $path
    $acl.SetAccessRuleProtection($true, $false)
    
    # Remove all non-SYSTEM access
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    
    # Grant SYSTEM full control
    $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($systemRule)
    
    Set-Acl $path $acl
}
```

---

## Monitoring Requirements

### SOC Dashboard Elements

1. **EDR Health Status**
   - Total onboarded devices
   - Healthy devices percentage
   - Devices with telemetry gaps
   - Average time to last telemetry

2. **AppLocker Activity**
   - Policy changes (last 24h)
   - Blocked execution attempts
   - Service configuration changes
   - Registry modifications

3. **Critical Process Status**
   - Devices with missing Defender processes
   - Service failure counts
   - Restart/reboot events correlation

4. **Threat Indicators**
   - Suspicious PowerShell executions
   - Encoded command usage
   - Admin privilege escalations
   - Lateral movement attempts

### Alert Severity Matrix

| Indicator | Severity | Response SLA | Auto-Action |
|-----------|----------|--------------|-------------|
| Defender process blocked | Critical | 5 minutes | Isolate device, create incident |
| Multiple AppLocker changes | High | 15 minutes | Alert SOC, collect forensics |
| AppID service enabled | Medium | 1 hour | Add to watchlist |
| Single policy change (authorized) | Low | 4 hours | Log for audit |

---

## Testing & Validation

### Pre-Production Testing

#### Test Environment Setup:

1. **Isolated Test Lab**
   - 3 Windows 11 VMs (24H2)
   - Domain controller
   - MDE workspace (test subscription)
   - No production connectivity

2. **Test Scenarios**

**Scenario 1: Baseline Functionality**
```powershell
# Verify all preventive controls work
# Expected: GhostLocker.exe blocked or detected
.\GhostLocker_Defender.exe
```

**Scenario 2: Detection Validation**
```powershell
# Manually create AppLocker rule
# Expected: All 8 MDE queries trigger alerts within 15 minutes
Set-AppLockerPolicy -XMLPolicy C:\Test\DenyRule.xml
```

**Scenario 3: Incident Response**
```powershell
# Simulate full attack
# Expected: Complete cleanup and restoration within 2 hours
# Run GhostLocker → Reboot → Run cleanup → Verify recovery
```

**Scenario 4: False Positive Testing**
```powershell
# Legitimate AppLocker usage
# Expected: No alerts for authorized changes
Set-AppLockerPolicy -XMLPolicy C:\Policies\Legitimate.xml -Merge
```

### Production Validation (Phased Rollout)

**Phase 1: Pilot (Week 1)**
- Deploy to 10 IT admin workstations
- Monitor for false positives
- Validate alert routing

**Phase 2: Limited Deployment (Week 2-3)**
- Deploy to 100 devices across different departments
- 24/7 SOC monitoring
- Weekly review meetings

**Phase 3: Organization-Wide (Week 4+)**
- Deploy to all devices
- Automated reporting
- Monthly effectiveness reviews

### Success Metrics

| Metric | Baseline | Target | Measurement |
|--------|----------|--------|-------------|
| Detection time | N/A | <15 min | Time from attack to first alert |
| Containment time | N/A | <30 min | Time from alert to isolation |
| Recovery time | N/A | <2 hours | Time from incident to full EDR restore |
| False positive rate | N/A | <5% | (False positives / Total alerts) × 100 |
| Coverage | N/A | 100% | Devices with monitoring enabled |

---

## Quick Reference Guide

### Emergency Response Checklist

**IF MDE DEVICE GOES UNHEALTHY:**

- [ ] Run MDE Query #3 (Defender Process Blocking)
- [ ] Check AppLocker policies: `Get-AppLockerPolicy -Effective`
- [ ] Isolate device if attack confirmed
- [ ] Collect forensics (policy XML, event logs, registry)
- [ ] Run `Complete_Cleanup.ps1`
- [ ] Reboot device
- [ ] Verify Defender processes: `Get-Process MsSense,MsMpEng,NisSrv`
- [ ] Check MDE portal for telemetry restoration
- [ ] Investigate root cause

### Key PowerShell Commands

```powershell
# Check AppID services
Get-Service AppID,AppIDSvc | Format-Table Name,Status,StartType

# Check AppLocker policies
Get-AppLockerPolicy -Effective | Format-List

# Check Defender processes
Get-Process | Where-Object { $_.Name -match "Sense|MsMp|NisSrv" }

# Check Defender services
Get-Service *Defender*,*Sense* | Format-Table Name,Status,StartType

# Remove AppLocker policies
Set-AppLockerPolicy -PolicyObject (New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy)

# Emergency cleanup
Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Recurse -Force
Remove-Item "C:\Windows\System32\GroupPolicy" -Recurse -Force
gpupdate /force
Restart-Computer -Force
```

### Critical Registry Paths

```
AppLocker Policies:
HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2

Legacy SRP:
HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer

AppID Driver Cache:
HKLM\SYSTEM\CurrentControlSet\Control\Srp

Defender Configuration:
HKLM\SOFTWARE\Microsoft\Windows Defender
```

### Important Event IDs

```
AppLocker:
8001 - Rule collection was applied
8002 - File allowed to run
8003 - File audited
8004 - File was blocked from running
8006 - DLL rule was applied
8007 - DLL blocked

Service Changes:
7036 - Service entered running/stopped state
7040 - Service start type changed
```

---

## Additional Resources

- **Microsoft Documentation:** https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/
- **AppLocker Technical Reference:** https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/
- **MDE Advanced Hunting:** https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview
- **Original Research:** https://github.com/zero2504/EDR-GhostLocker

---

## Document Change Log

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Dec 27, 2025 | CyberScroll | Initial release |

---

**CLASSIFICATION:** Internal Use Only  
**DISTRIBUTION:** Security Team, SOC, IT Operations

---

END OF DOCUMENT
