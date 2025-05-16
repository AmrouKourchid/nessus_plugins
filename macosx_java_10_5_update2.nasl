#TRUSTED 8397845e67454b41e06301f64dd5389931ac6750dba0969c51ec9598cd614a1afefc191677fd6eea4a0c6959b17678f0768fdadc9a0a0d1028b78801d038e8985d024ac014d1be7de17a45a3d8948a7287903ea07b8017bd6252d70f522fc045183037e45a6630bee7f01cba44874c8021bd2b340a0b4b1e65bc8b5e01aaa332c7a77c2352213762edc86883bfd9b4cd661365a94c3afa5f19d3dde3edeaf822298448587b7fa43e1516645af6a8cbae678b1a453f56218366687bfb6bb170e480a59c6143310bb85d2cd10fa85574f44c8ca08d1f0b06c693c5dd7528d022e7892563ad04eda66c73dd3ec12f3728ff18fd6f5f31ec23ef6a816cbe5b10eb059ae559aff6b743be8790e8e96d9cfd6c0a8df37b8a1399dfb549272a0db99f8cfe1c4964da444fdf1650d181583ee0d7d98b5fa626787cdc2fa8887b46028709b8f86266bd1dde197aaa331007e1ba7da27d34b587c53da89ab1d28e220779124298849cb4ab4033e4fcaadbcaeceff48e4776eb414d775e85c1ab88352240351f99921e93d4b975d7e6245c016ff9f978d919d9eb7c93b31ea828e12a3dc70cf595e05555ef0dfbb99a4f94ea07aa5a3e8fdfccda367ed643b8c50c9476bf559f28f6810924ea4ec2e4169b8b776ca1481230586193c41c639476a60a7676a2f96e6953ab8193f909a183a63514c560a8b488c6fbe6ae785f75890f389b7b3c
#TRUST-RSA-SHA256 4db60932e631c1dad7e512c59f4d69088d0a07b7577013b40a4b796e091631779114514693aa5f156763751895012bfcf634bf233f19b74701a93943b34cb86606efaf90e718917dde1d60bffb33b0be2a22c4e0e142d03e2dcafe48c9aaead6087578120117f56d24021e9f510c0b1aba74930ec104488ab0777b3d061f196f5a8d0a419559815473b5854b6842d47e476f202a0cd4ccf64037010c77cd6a0c286a0b77ddfb643a30e7b9df7aede4ebde26912c178ee554fea6a63a7a4e3c21eec439741110dfdabeed7ca3c02afcdf6f437edf8c531c72ddeda80291f4d3959631eaeb5fdb4cd9f765028a853b1b8ff123431763a561ca4cf7b10ad78f233a506314b3ccff9323191b8cdb863f9f99362b17941b828c7d11705cf881eb9a6797a984deff2cb77b5d2874ac2d4cc91ca8d3a9907c50dc10682dcbf89587aba3bfeff8577c7d1a557cc93a444a28477952006c3aeedd408b503443578d3efa04ec163f048d7d022c0aa6e57239b240e684938c580715fd549e231aa3256ed0ab7da987ed83cacf95e44e33df1b3596a6453334e33eacc68fcb73ec044b9ae47ab6de5e81267b50bb21b1077fbf0d94c8a65e011e0691865ab3a5456b8e5ca0e3880662489276b1756aa5d7e7dd72f581a4ff29f03e7ae43b98c7c5e710b9720690bc43b3135a66cabe2dba9549e1edadccad7776aafab6142d768a9de60b7447
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(34290);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id(
  "CVE-2008-1185",
  "CVE-2008-1186",
  "CVE-2008-1187",
  "CVE-2008-1188",
  "CVE-2008-1189",
  "CVE-2008-1190",
  "CVE-2008-1191",
  "CVE-2008-1192",
  "CVE-2008-1193",
  "CVE-2008-1194",
  "CVE-2008-1195",
  "CVE-2008-1196",
  "CVE-2008-3103",
  "CVE-2008-3104",
  "CVE-2008-3105",
  "CVE-2008-3106",
  "CVE-2008-3107",
  "CVE-2008-3108",
  "CVE-2008-3109",
  "CVE-2008-3110",
  "CVE-2008-3111",
  "CVE-2008-3112",
  "CVE-2008-3113",
  "CVE-2008-3114",
  "CVE-2008-3115",
  "CVE-2008-3637",
  "CVE-2008-3638"
 );
 script_bugtraq_id(28125, 30144, 30146, 31379, 31380);

 script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 2");
 script_summary(english:"Check for Java Update 2 on Mac OS X 10.5");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.5 host is running a version of Java for Mac OS X
that is missing update 2.

The remote version of this software contains several security
vulnerabilities that may allow a rogue Java applet to execute arbitrary
code on the remote host.

To exploit these flaws, an attacker would need to lure an attacker into
executing a rogue Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3179");
 # http://lists.apple.com/archives/security-announce/2008/Sep/msg00007.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdff3291");
 script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.5 update 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3113");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(264);

 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/25");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2024 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

if ( ! defined_func("bn_random") ) exit(0);


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
# Mac OS X 10.5 only
if ( egrep(pattern:"Darwin.* 9\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 12.2.0
 if ( int(array[0]) < 12 ||
     (int(array[0]) == 12 && int(array[1]) < 2 ) )
 {
   security_hole(0);
 }
}
