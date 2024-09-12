$source = @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;

namespace PingCastle
{
    public class TestAV
    {

      [DllImport("advapi32.dll", SetLastError = true)]
		static extern bool LookupAccountName(
			string lpSystemName,
			string lpAccountName,
			[MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
			ref uint cbSid,
			StringBuilder ReferencedDomainName,
			ref uint cchReferencedDomainName,
			out SID_NAME_USE peUse);


        const int NO_ERROR = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 122;
        const int ERROR_INVALID_FLAGS = 1004;

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

		public static SecurityIdentifier ConvertNameToSID(string accountName, string server)
		{
			byte [] Sid = null;
			uint cbSid = 0;
			StringBuilder referencedDomainName = new StringBuilder();
			uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
			SID_NAME_USE sidUse;

			int err = NO_ERROR;
			if (LookupAccountName(server, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
			{
				return new SecurityIdentifier(Sid, 0);
			}
			else
			{
				err = Marshal.GetLastWin32Error();
				if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_INVALID_FLAGS)
				{
					Sid = new byte[cbSid];
					referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
					err = NO_ERROR;
					if (LookupAccountName(null, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
					{
						return new SecurityIdentifier(Sid, 0);
					}
				}
			}
			return null;
		}

        static Dictionary<string, string> AVReference = new Dictionary<string, string>{
			
			{"avast! Antivirus", "Avast"},
			{"aswBcc", "Avast"},
			{"Avast Business Console Client Antivirus Service", "Avast"},

			{"epag", "Bitdefender Endpoint Agent"},
			{"EPIntegrationService", "Bitdefender Endpoint Integration Service"},
			{"EPProtectedService", "Bitdefender Endpoint Protected Service"},
			{"epredline", "Bitdefender Endpoint Redline Services"},
			{"EPSecurityService", "Bitdefender Endpoint Security Service"},
			{"BDAuxSrv", "Bitdefender Auxiliary Service"},
   			{"UPDATESRV", "Bitdefender Desktop Update Service"},
			{"VSSERV", "Bitdefender Virus Shield"},
   			{"bdredline", "Bitdefender RedLine Service"},
       			{"EPUpdateService", "Bitdefender Agent RedLine Service"},

      			{"CSFalconService", "CrowdStrike Falcon Sensor Service"},
			{"bdredline_agent", "CrowdStrike Falcon Sensor Service"},

			{"xdrhealth", "Cortex XDR Health Helper"},
      			{"cyserver", "Cortex XDR"},
	 
			{"CylanceSvc", "Cylance"},
   			
      			{"CybereasonActiveProbe", "Cybereason Active Probe"},
      			{"CybereasonCRS", "Cybereason Anti-Ransomware"},
	       		{"CybereasonBlocki", "Cybereason Execution Prevention"},

			{"EraAgentSvc", "ESET Management Agent service"},
   			{"ekm", "ESET"},
			{"epfw", "ESET"}, 
			{"epfwlwf", "ESET"}, 
			{"epfwwfp" , "ESET"},
   			{"ERAAgent", "ESET Management Agent service"},
     			{"efwd", "ESET Communication Forwarding Service"},
      			{"ehttpsrv", "ESET HTTP Server"},

      			{"AVKWCtl", "Anti-virus Kit Window Control"},
	       		{"AVKProxy", "G Data AntiVirus Proxy Service"},
	         	{"GDScan", "GDSG Data AntiVirus Scan Service"},

			{"xagt" , "FireEye Endpoint Agent"}, 

			{"fgprocsvc" , "ForeScout Remote Inspection Service"}, 
			{"SecureConnector" , "ForeScout SecureConnector Service"}, 

			{"fsdevcon", "F-Secure"},
			{"FSDFWD", "F-Secure"},
			{"F-Secure Network Request Broker", "F-Secure"},
			{"FSMA", "F-Secure"},
			{"FSORSPClient", "F-Secure"},

			{"klif", "Kasperksky"},
			{"klim", "Kasperksky"},
			{"kltdi", "Kasperksky"},
			{"kavfsslp", "Kasperksky"},
			{"KAVFSGT", "Kasperksky"},
			{"KAVFS", "Kasperksky"},

   	          	{"mfetp","Trellix Endpoint Threat Prevention Service"},
	    		{"mfeaack","Trellix Anti-Malware Core Service"},
	       	        {"mfemactl","Trellix Management Service"},
			{"enterceptagent", "MacAfee"},
			{"macmnsvc", "MacAfee Agent Common Services"},
			{"masvc", "MacAfee Agent Service"},
			{"McAfeeFramework", "MacAfee Agent Backwards Compatiblity Service"},
			{"McAfeeEngineService", "MacAfee"},
			{"mfefire", "MacAfee Firewall Core Service"},
			{"mfemms", "MacAfee Service Controller"},
			{"mfevtp", "MacAfee Validation Trust Protection Service"},
			{"mfewc", "MacAfee Endpoint Security Web Control Service"},
   	    		{"McAfee Endpoint Security Platform Service","Trellix Core Service"},
	          	
       			{"Parity", "Carbon Black App Control Agent"},
      
      			{"AcronisActiveProtectionService", "Acronis Active Protection Service"},

			{"PandaAetherAgent", "Panda Endpoint Agent"},
   			{"PSUAService", "Panda Product Service"},
      			{"NanoServiceMain", "Panda Cloud Antivirus Service"},
	 
			{"cyverak", "PaloAlto Traps KernelDriver"},
			{"cyvrmtgn", "PaloAlto Traps KernelDriver"},
			{"cyvrfsfd", "PaloAlto Traps FileSystemDriver"},
			{"cyserver", "PaloAlto Traps Reporting Service"},
			{"CyveraService", "PaloAlto Traps"},
			{"tlaservice", "PaloAlto Traps Local Analysis Service"},
			{"twdservice", "PaloAlto Traps Watchdog Service"},
			
			{"SentinelAgent", "SentinelOne"},
			{"SentinelHelperService", "SentinelOne"},
			{"SentinelStaticEngine ", "SentinelIbe Static Service"},
			{"LogProcessorService ", "SentinelOne Agent Log Processing Service"},

   			{"SntpService", "Sophos Network Threat Protection"},
      			{"Sophos Endpoint Defense Service","Sophos Endpoint Defense Service"},
	       		{"Sophos Live Query","Sophos Live Query"},
	   	      	{"Sophos Managed Threat Response","Sophos Managed Threat Response"},
			{"sophosssp", "Sophos"},
			{"Sophos Agent", "Sophos"},
			{"Sophos AutoUpdate Service", "Sophos"},
			{"Sophos Clean Service", "Sophos"},
			{"Sophos Device Control Service", "Sophos"},
			{"Sophos File Scanner Service", "Sophos"},
			{"Sophos Health Service", "Sophos"},
			{"Sophos MCS Agent", "Sophos"},
			{"Sophos MCS Client", "Sophos"},
			{"Sophos Message Router", "Sophos"},
			{"Sophos Safestore Service", "Sophos"},
			{"Sophos System Protection Service", "Sophos"},
			{"Sophos Web Control Service", "Sophos"},
			{"sophossps", "Sophos"},

			{"SepMasterService" , "Symantec Endpoint Protection"},
			{"SNAC" , "Symantec Network Access Control"},
			{"Symantec System Recovery" , "Symantec System Recovery"},
			{"Smcinst", "Symantec Connect"},
			{"SmcService", "Symantec Connect"},
   			{"SepScanService", "Symantec Endpoint Protection Scan Services"},

    	    		{"Trend Micro Endpoint Basecamp","Trend Micro Endpoint Basecamp"},
	   	    	{"TMBMServer","Trend Micro Unauthorized Change Prevention Service"},
	   	    	{"Trend Micro Web Service Communicator","Trend Micro Web Service Communicator"},
	  		{"AMSP", "Trend"},
     			{"TMiACAgentSvc", "Trend Micro Application Control Service (Agent)"},
			{"CETASvc", "Trend Micro Cloud Endpoint Telemetry Service"},
			{"iVPAgent", "Trend Micro Vulnerability Protection Service (Agent)"},
			{"tmcomm", "Trend"},
			{"tmactmon", "Trend"},
			{"tmevtmgr", "Trend"},
			{"ntrtscan", "Trend Micro Worry Free Business"},

			{"WRSVC", "Webroot"},

			{"WinDefend", "Windows Defender Antivirus Service"},
			{"Sense ", "Windows Defender Advanced Threat Protection Service"},
			{"WdNisSvc ", "Windows Defender Antivirus Network Inspection Service"},

			
		};


        public static void RunTestAV(string computer)
		{
			foreach (var entry in AVReference)
			{
				if (ConvertNameToSID("NT Service\\" + entry.Key, computer) != null)
				{
					Console.WriteLine("found: " + entry.Value + "(" + entry.Key + ")");
				}
			}
        }
    }

}
"@
Add-Type -TypeDefinition $Source

# Run example:
# [PingCastle.TestAV]::RunTestAV("192.168.0.25")
