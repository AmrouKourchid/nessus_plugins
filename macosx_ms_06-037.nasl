#TRUSTED 486d8670732e3a2083c80371cf302f89102be37eae3d38add6ff6763a2f3732bff77909957e8ba84f467f1447c93e8bb5d5c7931e2a2b5b25847ebaa4f7020e047f35827d84ff054f2fe73157293f9d7ce887e8c37284fd3287cb18f0b55586a212726b21b0f20aff122475d0a5c6347dfec2cd2b9486de74a9bd0a93534d997a7f5b48630a750a67318b9bbe5b9218e16a81efd6da912de02f5b6856248de0bac0dbad0e6d0e2efacddf5ff7e0dfa63064bcef27179512ad08e48bc21d1dbf24da68c41a4f3b9f7439961fddf483e020132ce47fd65648f8a27a49975f3db2385439f7fdb09d1c55e2943d4e4eac96ca505b82cb43e15d5de08e868dbde0173ed286e5d45fc3f7850c050ce338dddfa84043311e17580d0fdd69b5d9a1d3ef948ea6e703405649393b4ca89099562e16c9ce1e970567768aac75e926bd478873ec103f2f93bcb82d0a803a4ee78afaecc1c335527d415d141a216536f18331a15400f0a99629644f40c83c3657e01f64f1785712cae4135f58d3937816ca5cb60c11cb0078397806af637c175df37ac333736a3c263b84207fb985849d3be5051207b4f6e750cf8a97f9adb2ad0500e4eed7de2e4c9449910d2ce6e3ac2b4ce60e12be8bba136199ff30a0ad9d949263375b61bca23696c3689af4211ec327f61a0658d4e49b6265912fbbd710eea839300e2f43449d3cc24f81efcc8b72194
#TRUST-RSA-SHA256 ab97c80e43619974a4481c053528ce9af42dacb43262d9ab702aef4bd54266947bb287d033439646c94c9ca8acec6adb2db681cf13f7a0865be9628afa9f752df9781f52d1933010cc47000e8d72877defb5aab3837100bc0c9349dc79571ca4f5cf4958a5af3c15b545278a7cb339572f4296416910f42d70e4965dcb288b34bd2e3a4506d7fa9212e7abef0ff6e9d6d8107c7eb6cdf5e566841b03e6d839c3d718bae9153fc4fa4410bbfba6f5c286013cb60cb2950450514db26c7386f75cf1a5a870459c390ed8aacd424ee00e8a14aad83d500f2fa9590455f72ddb0a5d7f0a5d84be144a44896ce1019dff46a6525fd8a06ca7a498d5452cc76a4981df624741ea53ecc6c29e0e1801ebdff3430072015041bb16a02a180a57af8d8a80dfb1395d0b3669b0b4a9e23da615d0cce293f47bfe438a0d6333c73dfabb3a3b25ccc34c101d1f6fa07b886688968aaa644c89eced17e5d10479090bee8e470a3d682198e2375175871e8c0940dfa42aece6399dac1a98d92095dbffa43fd75290a3f28d7622369e798c15361c8f42d69d5066e8251d25065fddec0880244439661cb5545a0d9d672e098a50beee4030c092f5eff282a88cf2f7e70ee6b3cd34fee6d0948dd7ab95431dd8d2f5473d6dec74a72eb38b816f0de0f1f30da4b1f53a2e3f253faa4baa124eb28d50a4e677a2709800301e842b896076872c09ba75
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22025);
 script_version("1.34");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id(
  "CVE-2006-1301",
  "CVE-2006-1302",
  "CVE-2006-1304",
  "CVE-2006-1306",
  "CVE-2006-1308",
  "CVE-2006-1309",
  "CVE-2006-2388",
  "CVE-2006-3059",
  "CVE-2006-1316",
  "CVE-2006-1318",
  "CVE-2006-1540",
  "CVE-2006-2389"
 );
 script_bugtraq_id(
  18422,
  18853,
  18885,
  18886,
  18888,
  18889,
  18890,
  18910,
  18911,
  18912,
  18938
 );
 script_xref(name:"MSFT", value:"MS06-037");
 script_xref(name:"MSFT", value:"MS06-038");
 script_xref(name:"MSKB", value:"917284");
 script_xref(name:"MSKB", value:"917285");

 script_name(english:"MS06-037 / MS06-038: Vulnerabilities in Microsoft Excel and Office Could Allow Remote Code Execution (917284 / 917285) (Mac OS X)");
 script_summary(english:"Check for Excel 2004 and X");

 script_set_attribute(
  attribute:"synopsis",
  value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is running a version of Microsoft Office that is
affected by various flaws that may allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Excel or
another Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-037");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-038");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-3059");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2001:sr1:mac_os");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
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

uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  off2004 = GetCarbonVersionCmd(file:"Microsoft Excel", path:"/Applications/Microsoft Office 2004");
  offX    = GetCarbonVersionCmd(file:"Microsoft Excel", path:"/Applications/Microsoft Office X");
  if ( ! islocalhost() )
  {
   ret = info_connect();
   if ( ! ret ) exit(0);
   buf = info_send_cmd(cmd:off2004);
   if ( buf !~ "^11" )
   buf = info_send_cmd(cmd:offX);
   if (info_t == INFO_SSH)
     ssh_close_connection();
  }
  else
  {
  buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", off2004));
  if ( buf !~ "^11" )
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", offX));
  }


 if ( buf =~ "^(10\.|11\.)" )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
	  # < 10.1.7
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_warning(0);
	  else
          # < 11.2.5
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 5 ) ) ) security_warning(0);
	}
}
