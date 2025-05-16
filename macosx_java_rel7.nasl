#TRUSTED 654db84ce77549291118e0e8cb606352bf4f059831b6c97882657c97bc1e320ea0000241f8121c1d65eacb7774a9d7d7f4ff4355f0a404a2ad063b83164b9d632b0e96977a62b4157c8e865e7a2f5034affa322653805f76d1ce793b6aea9587e80927609ac4cc7c494d443fd3626c09f1e056f45cd45a493d966f76c2b7becb12258cc68b2b4996fe004032f559f721a15f7b70eb49471f13bc67991a3f4d53d3ba57aa79adde1378edfb07e48a600183841cdf377b980a256ae5e89bb4fae01cc86ef0ed8c61ff47fde9f76867b7fa1883e50403bd95cd41818b62199dbea0890b8f43204e23ef12dd4fe7c2f4ae72b694827a1577fa0b3a344d496430fc7fedfd323fcc525de5a98f59ccc188d2455a730684f4c8ef7cbed07135cf9b2585984bb4df8651b19e5e48f7270481018f704c46ba613b8997cc002538d088697153e1fe1b52eb205a77cb40c9626e185f3f7725700c7525f82555f1b7200d76df1f41f2d5aa2d51aa89a73006801298d1c2b0593c97c5efb077cb3a33c24007950e67d308a49e406276938c85058aa95c1c5b045d1e02fda39e0a09b988134008a46ec8c9b838f2b12d6bedf4a33190f45d322431f4eb5ca95879f9bf7f7da7bdd35c1c47e7b930c91f9bab83737d6794b19ef9132a6ec11040d06ccf2c65bc350e2e3095033312764f2718a495f09e2527af5acfb349ab117e72705f2adbfb08
#TRUST-RSA-SHA256 96c27d699ba316db96713f1572b191a95de78da2cdc3dedb937c26d384143b124d826e549a8819e2929df9ef2b79636842d22ee8f76847b5cc9be2cd1853784aeb8042902bd17e2799698404e0d92c23f90bef75a02fb0383ec3b86d0c397b41eb00c67a5ac2c11379ec5e9497d69a14028777ff1784e83b6c0005a32f8bc9a3d5758f6c30de30de2589626afbe671f234aba4377a93bc4119f7900386b74d8b69b662c0d9d526475d2a0c8bbb564e7a871b03c7a4365628064d685d0fa70e4aba9478599cc899d3765650581ba4f8a8a9e2b3cd36f0567bd19d053840d8c0641c9ed52fef9160d1fff4ca90736825fc8afb5b49efb97045b0061af42683f4b6a87490a38152e58f1fd234c12e2231bc49b2de986eb2aea224d764fe69161e3fb311ca7552f9d399c59dc05c9347806b167c758e17df1b44643241dac42c607c6c4e0db27c8b0279fa4dd107032f89156947ea912e679b0ced83d20739311ad023d76f3c9f7ae3840bcadbbe5ae51ed79276b6aaf7a5d1d26f2ef02358692741fb90caebd0e57023f29bd682495c552221e000eda4252cb37fd0396f953d8efebbb733c80a0967db62304a91a6aa01fdb324fc39b9e6143c8de4cece75b154e24099e20c90b570815e034ebd8347408d292e5f3dad9fcd7f0bea190516568eb6956dd39eb40fe6d917d3854c7e75f23f51b569fd58198b0d6885c6b98a99c03e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34291);
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

 script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 7");
 script_summary(english:"Check for Java Release 7 on Mac OS X 10.4");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS X
that is older than release 7.

The remote version of this software contains several security
vulnerabilities which may allow a rogue java applet to execute arbitrary
code on the remote host.

To exploit these flaws, an attacker would need to lure an attacker into
executing a rogue Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3178");
 # http://lists.apple.com/archives/security-announce/2008/Sep/msg00008.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6768324f");
 script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 7 or later.");
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
# Mac OS X 10.4.11 only
if ( egrep(pattern:"Darwin.* 8\.11\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 11.8.0
 if ( int(array[0]) < 11 ||
     (int(array[0]) == 11 && int(array[1]) < 8 ) )
 {
   security_hole(0);
 }
}
