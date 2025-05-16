#TRUSTED 89e5a5fd0d89fa119533ef0565c96e1d2aa53e337bf5102b7dcf7d55eb2886286e783f258cad888e1b9171214c8ef24ff0f9315edf6f561fd04d7557fc8fe5b8772449df53a5ba8a8be570554bc8c4a8718ae9b6c691e654b61764a0a89530b6ac92a90c9a2e22343951940a305d560a6fc96517b916608955616d2d6a2fa917bf5edcd7604c1405590141bbdb94b86b84c7e01f4cd35dced40b5c13d97d3fe8c2b2ceece80e6fe3c2af5542e27895f0850ae9a990bf0f346e7be04a3309252a34a0fd9bcc2b25cb962af75a403cbc90429e0bab916090716672460ab704ba763ecc69022c065fb6e183e7fb1bb88406a1eb32e9d144ceb0561a9331ee7d6cdafb3399824fd126bccdca045d61a281ea1c2cb5341addc466ad1831ef8a4fa7bccb925a7f928d2bc572863af52feea68008afbc1c94867f588a03c38185e72806a4725d48a6641b217e7cdd9d2d267ff8c63661cdae7b84343bdcf06480624c7ab2344e378f274c1c366ee28141c25ab3a0fd28274d25120e0c7110754165f456d89f5b85ed3d73b7f27ecb2ac1dc590051e34d56e8d45f396261ad22f880597e84f625f6caa7b8dc73601228cb90ff38347b41c65d1273b79e9d06bc90d43aefa96a25b70039acf63b1211dfea6b2cb149f5e7537897295a720e18af4723f2a9c48bc756d4d7c4bdffbd4b7d6806b8399d62b7139525ded57c263ada4a5fd58c
#TRUST-RSA-SHA256 7f5e9b18ee50c78de7de3c9ff321c00f55d486334aa178de045b8c4c83c830c17e9887417d7539e4036b3dad36cd69a326337a84c394b939564d50b5f01f41a366605067efe1ad550fa1d25dba665d528ffd8d1850447d3c6eee0ff04da111781d22bd6ace1b8422588f4b8acd500f406b9821077815abab6cfdf06de71bf8b5aebd13096de573bf0d99f0372174b055d77fc5be4ebdd3b1778b8cb98fc90d7d9f1a3016fb3c749c32071fc7a63e13a28a23ffd7e5d53c669701534f2e056fb45b51a90e216dc072fffef15442c54b42cfba0c817a42b62781f88601ddc8c36c578ab47e23badb8f77a7d36cb18d13a108bf8bdedf10962e5c74a003f56a5aea613de3faee964a8111a0d5bf7cb39fc8fb6b788baf101253dee601dba28284740ad00a1c5dfc689a5c45e27c0d3129151ffdbbbe962ea21b0f573f80264970c3f0008c1a68391c6ba954f85c51a23e065275cc1ee17900af9904e44f1db0139e78f9a67a6ee0a404adb6630028237977917bf9e43b6434ea628b4c7482365a9cd0b3ea07b35beaf743c221e96c12766db84f120ef4948064df69a82481b0b32851af5196f48209024d4c76bafa272af3606b1597ec54010a513bc929585310201001f2c9fc1aca298361fb7071aeeced183d27e967a3956344bf048e753f27ef93b92e1d789720409177e1c3bf7fe9b53f857b2145bcb246c02851891119ba9b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(29702);
 script_version("1.23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id(
  "CVE-2006-4339",
  "CVE-2006-6731",
  "CVE-2006-6736",
  "CVE-2006-6745",
  "CVE-2007-0243",
  "CVE-2007-2435",
  "CVE-2007-2788",
  "CVE-2007-2789",
  "CVE-2007-3503",
  "CVE-2007-3504",
  "CVE-2007-3655",
  "CVE-2007-3698",
  "CVE-2007-3922",
  "CVE-2007-4381",
  "CVE-2007-5232",
  "CVE-2007-5862"
 );
 script_bugtraq_id(
  21673,
  21674,
  21675,
  22085,
  24690,
  24695,
  24832,
  24846,
  25054,
  25340,
  25918,
  26877
 );
 script_xref(name:"EDB-ID", value:"30284");

 script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 6");
 script_summary(english:"Check for Java Release 6");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS
X that is older than release 6.

The remote version of this software contains several security
vulnerabilities that may allow a rogue Java applet to escalate its
privileges and to add or remove arbitrary items from the user's
KeyChain.

To exploit these flaws, an attacker would need to lure an attacker
into executing a rogue Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307177");
 script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 6.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-2435");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/07/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/17");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2024 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

function exec(cmd)
{
 local_var ret, buf;

 if ( islocalhost() )
  buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
 else
 {
  ret = info_connect();
  if ( ! ret ) exit(0);
  buf = info_send_cmd(cmd:cmd);
  if (info_t == INFO_SSH)
    ssh_close_connection();
 }

 if ( buf !~ "^[0-9]" ) exit(0);

 buf = chomp(buf);
 return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# Mac OS X 10.4.10, 10.4.11 only
if ( egrep(pattern:"Darwin.* 8\.(10|11)\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 if ( int(array[0]) < 11 ||
     (int(array[0]) == 11 && int(array[1]) <= 7 ) )
 {
  cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"SourceVersion");
  buf = exec(cmd:cmd);
  if ( strlen(buf) && int(buf) < 1120000 ) security_hole(0);
 }
}
