##################################      Import needed modules      ##################################
Install-Module PSWriteColor



##################################      Configure CLI Parameters      ##################################
$IgnoreKnown = $args[0]
### ---> Use this switch to look for suspicious services on servers, instead of just reviewing server config



if($args[0] -eq $null){
	write-host @"
	NAME
		serverServiceScanner.ps1

	SYNOPSIS
		Pull service information from servers.  Optionally, exclude known services to only look for out-of-place services.

	SYNTAX
		serverServiceScanner.ps1 [Full | IgnoreKnown]

	DESCRIPTION
		If you want to see all non-Windows services, use 'serverServiceScanner.ps1 Full'.  This is useful for building documentation about services, and creating documentation about server topology.

		If you want to see all unknown services, use 'serverServiceScanner.ps1 IgnoreKnown'.  This is useful for researching apps and services installed on servers, to look for discrepancies or potential vulnerabilities.

		In order to run this properly, you must Right-click on the Powershell window, and select-object
		Run As Administrator.  You will probably also want to run as a domain user, to be able to access PSRemoting functionality.

"@
}

##################################      Set up functions      ##################################
####---->  http://theadminguy.com/2009/04/30/portscan-with-powershell/
function fastping{
  [CmdletBinding()]
  param(
  [String]$computername = $scanIp,
  [int]$delay = 1000
  )

  $ping = new-object System.Net.NetworkInformation.Ping  # see http://msdn.microsoft.com/en-us/library/system.net.networkinformation.ipstatus%28v=vs.110%29.aspx
  try {
    if ($ping.send($computername,$delay).status -ne "Success") {
      return $false;
    }
    else {
      return $true;
    }
  } catch {
    return $false;
  }
}



##################################      Set up variables      ##################################
### ---> These are regular Windows services we can safely ignore
###        -See https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server#activex-installer-axinstsv

$services = "AeLookupSvc",`
"ALG",`
"AppIDSvc",`
"Appinfo",`
"AppMgmt",`
"AppReadiness",`
"AppXSvc",`
"AudioEndpointBuilder",`
"Audiosrv",`
"BFE",`
"BITS",`
"BrokerInfrastructure",`
"Browser",`
"CertPropSvc",`
"COMSysApp",`
"CryptSvc",`
"DcomLaunch",`
"defragsvc",`
"DeviceAssociationService",`
"DeviceInstall",`
"Dhcp",`
"DiagTrack",`
"Dnscache",`
"dot3svc",`
"DPS",`
"DsmSvc",`
"Eaphost",`
"EFS",`
"EventLog",`
"EventSystem",`
"fdPHost",`
"FDResPub",`
"FontCache",`
"FontCache3.0.0.0",`
"gpsvc",`
"hidserv",`
"hkmsvc",`
"IEEtwCollectorService",`
"IKEEXT",`
"iphlpsvc",`
"KeyIso",`
"KPSSVC",`
"KtmRm",`
"LanmanServer",`
"LanmanWorkstation",`
"lltdsvc",`
"lmhosts",`
"LSM",`
"MMCSS",`
"MpsSvc",`
"MSDTC",`
"MSiSCSI",`
"msiserver",`
"napagent",`
"NcaSvc",`
"Netlogon",`
"Netman",`
"netprofm",`
"NetTcpPortSharing",`
"NlaSvc",`
"nsi",`
"PerfHost",`
"pla",`
"PlugPlay",`
"PolicyAgent",`
"Power",`
"PrintNotify",`
"ProfSvc",`
"RasAuto",`
"RasMan",`
"RemoteAccess",`
"RemoteRegistry",`
"RpcEptMapper",`
"RpcLocator",`
"RpcSs",`
"RSoPProv",`
"sacsvr",`
"SamSs",`
"SCardSvr",`
"ScDeviceEnum",`
"Schedule",`
"SCPolicySvc",`
"seclogon",`
"SENS",`
"SessionEnv",`
"SharedAccess",`
"ShellHWDetection",`
"smphost",`
"SNMPTRAP",`
"Spooler",`
"sppsvc",`
"SSDPSRV",`
"SstpSvc",`
"svsvc",`
"swprv",`
"SysMain",`
"SystemEventsBroker",`
"TapiSrv",`
"TermService",`
"Themes",`
"THREADORDER",`
"TieringEngineService",`
"TrkWks",`
"TrustedInstaller",`
"UALSVC",`
"UI0Detect",`
"UmRdpService",`
"upnphost",`
"VaultSvc",`
"vds",`
"vmicguestinterface",`
"vmicheartbeat",`
"vmickvpexchange",`
"vmicrdv",`
"vmicshutdown",`
"vmictimesync",`
"vmicvss",`
"vmms",`
"VSS",`
"W32Time",`
"Wcmsvc",`
"WcsPlugInService",`
"WdiServiceHost",`
"WdiSystemHost",`
"Wecsvc",`
"WEPHOSTSVC",`
"wercplsupport",`
"WerSvc",`
"WinHttpAutoProxySvc",`
"Winmgmt",`
"WinRM",`
"wmiApSrv",`
"WPDBusEnum",`
"WSService",`
"wuauserv",`
"wudfsvc",`
"FCRegSvc",`
"idsvc",`
"IPBusEnum",`
"NetMsmqActivator",`
"NetPipeActivator",`
"NetTcpActivator",`
"WAS",`
"TabletInputService",`
"TimeBroker",`
"stisvc",`
"wbengine",`
"vhdsvc",`
"nvspwmi",`
"sppuinotify",`
"UxSms",`
"ProtectedStorage",`
"AJRouter",`
"bthserv",`
"CDPSvc",`
"ClipSVC",`
"WinDefend",`
"XblAuthManager",`
"XblGameSave",`
"WSearch",`
"vmcompute",`
"Dfs",`
"DFSR",`
"DHCPServer",`
"DNS",`
"DsRoleSvc",`
"IsmServ",`
"Kdc",`
"KdsSvc",`
"NTDS",`
"NtFrs",`
"CertSvc",`
"TBS",`
"AxInstSV",`
"AppVClient",`
"CoreMessagingRegistrar",`
"CscService",`
"DcpSvc",`
"DevQueryBroker",`
"DmEnrollmentSvc",`
"dmwappushservice",`
"DsSvc",`
"embeddedmode",`
"EntAppSvc",`
"FrameServer",`
"HvHost",`
"icssvc",`
"lfsvc",`
"LicenseManager",`
"MapsBroker",`
"NNetSetupSvccbService",`
"NgcCtnrSvc",`
"NgcSvc",`
"OneSyncSvc_1e9564a2",`
"OneSyncSvc_1eabf8c2",`
"OneSyncSvc",`
"PcaSvc",`
"PhoneSvc",`
"PimIndexMaintenanceSvc_1e9564a2",`
"PimIndexMaintenanceSvc_1eabf8c2",`
"PimIndexMaintenanceSvc",`
"QWAVE",`
"RmSvc",`
"SensorDataService",`
"SensorService",`
"SensrSvc",`
"StateRepository",`
"StorSvc",`
"tiledatamodelsvc",`
"TimeBrokerSvc",`
"tzautoupdate",`
"UevAgentService",`
"UnistoreSvc_1e9564a2",`
"UnistoreSvc_1eabf8c2",`
"UnistoreSvc",`
"UserDataSvc_1e9564a2",`
"UserDataSvc_1eabf8c2",`
"UserDataSvc",`
"UserManager",`
"UsoSvc",`
"vmicvmsession",`
"WalletService",`
"WbioSrvc",`
"WdNisSvc",`
"WiaRpc",`
"wisvc",`
"wlidsvc",`
"WpnService",`
"WpnUserService_1e9564a2",`
"WpnUserService_1eabf8c2",`
"WpnUserService",`
"CDPUserSvc_1e9564a2",`
"CDPUserSvc_1eabf8c2",`
"CDPUserSvc",`
"hns",`
"TBS"



### ---> These are some services that we know about, but aren't necessarily standard to Windows
$knownservices = "aspnet_state",`
"clr_optimization_v2.0.50727_32",`
"clr_optimization_v2.0.50727_64",`
"clr_optimization_v4.0.30319_32",`
"clr_optimization_v4.0.30319_64",`
"dcevt64",`
"dcstor64",`
"omsad",`
"Server Administrator",`
"SQLAgent$ALSQLEXPRESS",`
"SQLBrowser",`
"SQLWriter",`
"MSSQLServerADHelper100",`
'MSSQL$ALSQLEXPRESS',`
'MSSQL$VEEAMSQL2012',`
'SQLAgent$VEEAMSQL2012',`
'SQLAgent$ALSQLEXPRESS',`
'MSSQL$ALSQLEXPRESS',`
"MSSQLFDLauncher",`
"MSSQLSERVER",`
"ReportServer",`
"SQLSERVERAGENT",`
"W3SVC",`
"IISADMIN",`
"w3logsvc",`
"ADSync",`
"ADWS",`
"AzureADConnectHealthSyncInsights",`
"AzureADConnectHealthSyncMonitor",`
"SPAdminV4",`
"SPSearchHostController",`
"SPTimerV4",`
"SPTraceV4",`
"SPUserCodeV4",`
"SPWriterV4",`
"c2wts",`
"Microsoft SharePoint Workspace Audit Service",`
"ose64",`
"OSearch15",`
"osppsvc",`
"ose",`
"MSExchangeAB",`
"MSExchangeAB",`
"MSExchangeADTopology",`
"MSExchangeAntispamUpdate",`
"MSExchangeEdgeSync",`
"MSExchangeFBA",`
"MSExchangeFDS",`
"MSExchangeImap4",`
"MSExchangeIS",`
"MSExchangeMailboxAssistants",`
"MSExchangeMailboxReplication",`
"MSExchangeMailSubmission",`
"MSExchangeMonitoring",`
"MSExchangePop3",`
"MSExchangeProtectedServiceHost",`
"MSExchangeRepl",`
"MSExchangeRPC",`
"MSExchangeSA",`
"MSExchangeSearch",`
"MSExchangeServiceHost",`
"MSExchangeThrottling",`
"MSExchangeTransport",`
"MSExchangeTransportLogSearch",`
"msftesql-Exchange",`
"wsbexchange",`
"MSSQL$VEEAMSQL2012",`
"SQLAgent$VEEAMSQL2012",`
"RIFRemoteInstallAgent",`
"RPCHTTPLBS",`
"diagnosticshub.standardcollector.service",`
"AppHostSvc",`
"MSMQ",`
"SQLTELEMETRY",`
"WMSVC",`
"drs",`
"msoidsvc",`
"VSStandardCollectorService140",`
"WatAdminSvc",`
"AllUserInstallAgent",`
"AppFabricCachingService",`
"DnsProxy"



if($IgnoreKnown -eq "IgnoreKnown"){
	$services = $services + $knownservices
}

if($IgnoreKnown -eq "Full"){
	$services = $services
}

$computers = "server1",
"server2",
"server3",
"server4",
"server5"


### ---> Need to set up a blank array for tuples
$svcarray = @()



#################################      Do the actual work      #################################
foreach ($server in $computers) {
	$serverup = fastping $server

	if($serverup){
		$serverservices = Get-Service -computername $server -Exclude $services -ErrorAction 'SilentlyContinue'
		$serverservicesname = $serverservices.Name
		$serverservicesdisplayname = $serverservices.DisplayName

		$s = 0
		$e = $serverservices.length
		if($e -gt 0){
			Do{
				$tup = New-Object "tuple[String,String,String]" $server,$serverservicesname[$s],$serverservicesdisplayname[$s]
				$svcarray += $tup
			} While(++$s -lt $e)
		}
	}
	else{
		write-host "$server is down..."
	}
}


$svcarray | select-object -property `
	@{Label="Server Name";Expression={$_.Item1}},@{Label="Service Name";Expression={$_.Item2}},@{Label="Display Name";Expression={$_.Item3}} | out-gridview -Title "Nonstandard Server Services"
