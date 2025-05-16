#TRUSTED 821844779203057c0d1b622ece1b485db2d3aa80ac489a26aed657c5b3be0abdab171c9bdb0b2dd0a089439be6fe539ef1417347b45d21e72103ef205859300e4c20694e6660e94711fcbe0601cd414026bae7de902528a94a6b5ac70c379e1164888473dbcfd519aff01daad99c1ee5ac98ec187db1aaaccc555d667539d7b5b757481808096c38cc27540b1de97e38097bdcac45bab38db1c43a796d641bc45cac7c05f80711b98e780efe87f3aa05d50579f5402e73bb90922bf3850b7c5d9d0b6f86503f65bf2bf74f8f59cb2bc0107125084af92903ae5563dac43cb033abd2f769ac39f9b343ca9c8ff012adbf17351e68d3a8bdd0dd55b86bf2c36946b6a34f5788bd88fb57e98635a78e12361b3e5dbcd370b17ad05d73bc7fe8ea8a82256b4e72a32eb7ea77191be9d116c676f3df1eac2d300bcafbf8cf06363e253531bd702c51b0564eba65082d222ff90478b4e0acfc6d2982320c829301c0034c4ecacefab3b6c1bc0f507e0a00bab555b12aa87d914b554c6d39027c9ffa469ec9db2c9806f335e8c8a620b4113355752bb85a1ff4161dd1a801c888a5bec0de08cc7ae2e855f7de261e26425a7f0051bf67d2b240906bff0850aaca56fb329c49580e3c0e7a36785bfb6a8dc1de11ee5ade50f93b65f8b7d7012d509ef0d38b28ba35b9b3d709f9fdf5b0e5ddd55dd994287781b501ac8b129c110a662d5e
#TRUST-RSA-SHA256 6a50761a68b0c0c9ca05c962f41d538de6c316c9b6d27ae94bd39e53137074cbcd96fcd0ea6b2534da52eea7caafaeeaf64ec69f58e3307d4c2824b894783cc709b3b31da4968d12b14c0a80e39f8ff99c52d2a67965f49db627cd0f562d532c84d2c6e8d743295456a1af7aff6482ce435dbd09d7998517b1597711799025d9ca8c761a4aad1608a39eb260367aa7056f8d3f95b005181a79b61dbad74764dd035d985bb2e7f6cc2285cc0da1f807042d23416f75c025d308aee2997da1d84e6e4dc1eacb9569393683d22ba9b187ce57374a75b113abf45ab474184f331b45666e1892b3938aa4a72acd79eb68982662386c4d50c24216cc39e9436ebddb70ce24896031ea9bc7b3c2983174e7e10bf14172f91eaa6a60a231d1931880d2623188095379dcf91c6520a5359591bf0e8894555201657681af7e3c339af81c69bc4ac6da56df810f2342534cdd7902bb7205e151e7ad84b7cd336f52b048aa5b195884b19716405443f63cd3da01da9caa317854cf712c12077a952cc2df22070fa6261998dbb735bb7f6c7ed5d1ae98eb5fa1486df574eba10db4a5fab41069a5cb755f19385bb92103b6f41d9aa2de8a0f3573e6486567588ada60d684d6de8da12a642cfd3a97f39b9d21a53200c5a6bbd1d9600facec3b9f953f919181fe119f5e1362728d9de23257e4083829d37ae2ef9deae94f8aa895f182e170824c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22418);
 script_version("1.29");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2006-3507", "CVE-2006-3508", "CVE-2006-3509");
 script_bugtraq_id(20144);

 script_name(english:"AirPort Update 2006-001 / Security Update 2006-005");
 script_summary(english:"Checks for the version of the Airport drivers");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the AirPort
Wireless card.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a security update regarding the drivers of
the AirPort wireless card.

An attacker in the proximity of the target host may exploit this flaw
by sending malformed 802.11 frames to the remote host and cause a
stack overflow resulting in a crash of arbitrary code execution.");
 script_set_attribute(attribute:"solution", value:
"Apple has released a patch for this issue :

http://docs.info.apple.com/article.html?artnum=304420");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-3509");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/09/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/21");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2024 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

function vulnerable()
{
 security_hole( port : 0 );
 if ( ! islocalhost() ) ssh_close_connection();
 exit(0);
}

function cmd()
{
 local_var buf;
 local_var ret;

 if ( islocalhost() )
	return pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", _FCT_ANON_ARGS[0]));

 ret = info_connect();
 if ( ! ret ) exit(0);
 buf = info_send_cmd(cmd:_FCT_ANON_ARGS[0]);
 if (info_t == INFO_SSH)
   ssh_close_connection();
 return buf;
}


uname = get_kb_item("Host/uname");
if ( "Darwin" >!< uname ) exit(0);


#
# Mac OS X < 10.4.7 is affected
#
if ( uname =~ "Version 8\.[0-6]\." ) vulnerable();

#
# Mac OS X < 10.3.9 is affected
#
if ( uname =~ "Version 7\.[0-8]\." ) vulnerable();



get_build   = "system_profiler SPSoftwareDataType";
has_airport = "system_profiler SPAirPortDataType";
atheros  = GetBundleVersionCmd(file:"AirPortAtheros5424.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/");
broadcom = GetBundleVersionCmd(file:"AppleAirPortBrcm4311.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/");



build = cmd(get_build);
airport = cmd(has_airport);
if ( "Wireless Card Type: AirPort" >!< airport ) exit(0);  # No airport card installed

#
# AirPort Update 2006-001
#	-> Mac OS X 10.4.7 Build 8J2135 and 8J2135a
#
if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J2135a?", string:build) )
{
 atheros_version = cmd(atheros);
 broadcom_version = cmd(broadcom);
 if ( atheros_version =~ "^1\." )
	{
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
	}
 if ( broadcom =~ "^1\." )
	{
	 v = split(broadcom_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 4 ) vulnerable();
	}
}
#
# Mac OS X Security Update 2006-005 (Tiger)
#	-> Mac OS X 10.4.7 build 8J135
#	-> Mac OS X 10.3.9 build 7W98
#
else if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J135", string:build) ||
          egrep(pattern:"System Version: Mac OS X 10\.3\.9 ", string:build) )
{
  cmd = GetBundleVersionCmd(file:"/AppleAirPort2.kext", path:"/System/Library/Extensions");
  airport_version = cmd(cmd);
  if ( airport_version =~ "^4\. " )
  {
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 4 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
  }
}


if ( ! islocalhost() ) ssh_close_connection();
