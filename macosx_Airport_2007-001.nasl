#TRUSTED 8606d1c809b0097daa4dbcd0df58b774353ae479853740ff11ef4a1e65f31c3b876dd95ef7e71659c41deba8af4ce0ac1023eee8fd83900bdec647a1273c3842d134cd992488fa1618ad40fb710c300ea04146677b6a22206108399cde11c7293d027cfd7a3eb4009de351889be53e83a749e4d1219f93a4da8ddff821e4433fb8c25058dbe7bb2cb58574c3d915f23ea43cf160237eafb6425e82bcbfaada95b5ca758b4f2bde33b534795015bdc9d44b0af5fefc3f94c7e69e13e432278ad95d136319265c27ce8c95522c81042b2f93b4b68f61de968fe3d49c53585526fac5e44531ea7ca63e205d805998de08777bf67d5d42ffe8eec13fd20d9c0e74ce4a4044ebc818ffc9690bacb79f8e5096243d65403751c51e447c71ac80bad3e5ccd65de2d0656f9d812cb73952dd8ad597add4fca78e85f31a31c764f6ca4f976b3c72519053eed069541399c363fd2b5012b987dc874f1cc83717c5dfecdca82fd8e59cff35338cc1f0476a891a47c4dbb51fcc36e98975d8db9ba7507dcd24135036d0f0c3dc21a0093d82313f733679a33b6ed386765817388939484e7185dc549447110911512fbd870acf0e2417c504ab567c55d330bd75e132695714ac19a7eb3ded23790077c24356b6e83ae49a11c38907ba7e7e038bf7f872c9f12521f94819bd093a47008db26070bd88cdee22f3ed58fc81cb8b0adb414868e0e2
#TRUST-RSA-SHA256 6e869da9aacc5e3ead9e5827c173d9d5ba3afce605058ae8d61b47c9752fc70864f329c552f7eb88a51ebe19b5bdbbdcfd80565f9941a25a0f3d819a9ba36bbcd8ccef89d632aa57cda1fae4ec756e4606e7f51e64be1a6dfccbbc54dba0a7548686036bb8954d2be7080a706281d1cc141638486685ec6377426055e6b5fbf462cc12c9ed6e3c0b78a102cf1023316bc106dcd173b1e8d744fe54936a2fc16a4e9d82869e946225d3436c5bc2849ad0bbbbe90ff42f2fe629643fd707b113d48c986db2d4d4c327f1894bdfe16ed6b5f25af81d960badc6f54ffe662606f5efe0865989a18a8523c5a8ad9fdfe2819aabd9c08695c73582a35f714ffdb956e342933ad28f19a7caa55bc32869e8756173bd82d2878b678996349e84b261f5a8d33ee84e511d663905e3a7e932629c69ee259fdf807994b4794f1399a06e8fdfa36f073cfc59afcac4f75839458186651eb6657eb6962e9742b92c4d005809ef14b073fcfc2aad4a81f2090476bb9cad3e6a641e091f77fcba1e3477ffe833fb3ae250a43d1e9e6bc64e4ec62d335e270506f832da7777b44c225a3a04bd7a283f3e51c81f37b743bca750fe61e894b769bf8363aee40080a3022d962e0ec14a75d74b15c595c8288e7318830fd6a1e53e49f782875d0c00a363a3d9e3f7066bb346423cd378e576e188328eedaf4f7d75f5950c171d27df27afce73ac8bd0d9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24241);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2006-6292");
 script_bugtraq_id(21383);

 script_name(english:"Mac OS X Airport Update 2007-001");
 script_summary(english:"Check for the presence of the SecUpdate 2007-001");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not have
Airport Update 2007-001 applied.

This update fixes a flaw in the wireless drivers that may allow an
attacker to crash a host by sending a malformed frame.");
 script_set_attribute(attribute:"solution", value:
"Install Airport Update 2007-001 :

http://www.nessus.org/u?0af16cb0");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305031");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-6292");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/30");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/01/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/26");

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


 buf = chomp(buf);
 return buf;
}

uname = get_kb_item("Host/uname");
if ( ! uname ) exit(0);
if ( ! egrep(pattern:"Darwin.* (8\.)", string:uname) ) exit(0);

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);
if (
  "AirPortExtremeUpdate2007001.pkg" >< packages ||
  "AirPortExtremeUpdate2007002.pkg" >< packages ||
  "AirPortExtremeUpdate2007003.pkg" >< packages ||
  "AirPortExtremeUpdate2007004.pkg" >< packages ||
  "AirPortExtremeUpdate200800" >< packages
) exit(0);

buf = exec(cmd:"system_profiler SPHardwareDataType");
if ( ! buf )exit(0);
if ("Intel Core Duo" >!< buf ) exit(0); # Only Core [1] Duo affected


cmd = _GetBundleVersionCmd(file:"AirPortAtheros5424.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns", label:"SourceVersion");
buf = exec(cmd:cmd);
if ( strlen(buf) && buf =~ "^[0-9]" && int(buf) < 2214600 ) { security_warning(0); exit(0); }

cmd = _GetBundleVersionCmd(file:"AppleAirPortBrcm4311.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns", label:"SourceVersion");
buf = exec(cmd:cmd);
if ( strlen(buf) && buf =~ "^[0-9]" && int(buf) < 2217601 ) { security_warning(0); exit(0); }
