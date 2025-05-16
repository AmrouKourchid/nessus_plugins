#TRUSTED 420cf33e5c710a1a0e01dd58ae5e8da46e35e3eccfd87f3386f20e8e953e8eec63d0009ca3a580ba56f634352b47dd158ca9f810afb2be3958b664fe6b4614a41c7ab9251b29a2da4fae72d32c6a4c44ee3c0b44b69c40d458e1b07c85c6385e49da0463105938f2d4370cf965e8aafd204b09e90738adbbccaf86c3cd656900cc3aae9c5c188ce22dcc31c8f458ddc813e91828c2e2936c2d0ff00747217d18f785d4f64cc8a229f9cc5a0d7f831c19ff213b8b404afcaa80e2d9dc4fd51695ccd7c1225cd5f84346d48cec0299ed6e797c0d69294d48e7646e27788c55979fabaa24de7542850a39ce0677852729d858662ac7990fe32d40a27a4d2c96812122f5fac10d72957e352b6d73bb6562160ac21df8810cdc798d3a4a870eb452b50207c5459dbea954efc8b60a56a32ba7105ef97e60603cdace75bd07aaaa786e6cd299e07fa7671ccaa905ec10f63e4ac0ae85e87ecc228e05340b0a6217438450259e0980e6fcbef9da2e0d277f4a15e3e827defe728b3b3f8ddc0a82fefbf9ddc05685534caf02fed5c73593530c89c58c6a3540ec5a89d87cbd06e89cd395991d4f649eb5b7213b173d86e7502205691b385a17c52e0808f8d125254e66818ea0b43f753abfdd659b9ec6353bd5485d918cd1aa67896354a18ff82dc82b7beb58779ba467ba2d61eff165b890a4737d97712ae74b4c6fb640f7ef1c56dd4a
#TRUST-RSA-SHA256 4c0cfa42e5c3bf6dc989525c35ca3e335a43c827ed5e24dd3e755504345008287e1c007ec0875ff5dafc34b39e6ca6c2361604bdbdab342bab46c06f09ad15390376d47b9ece4b605db301732e25f87f0996541e3b84b5207715d37712cbb97169cf58d9f33fd4245b0496b4619295461beae1f36b04a9e3d08b191ef947004e11e6193d09765e0028027a2a37da1031df1c4e18febbbd3b92ced142fc951dd499ccbb1616448b50fa042fee71e7b000ceeb469339575f9adfb6c6bcae46bf06e0f04ee4a2453796d2a652e9f0ba2cf44d1b8f83e972de56f4f032a32dba24da182fded205dadbd652d3d588dc0aecb1bcb6c671168d258b9903fab8e95b5ef4bdd9aad05521950724ad49f18c54d985e6ed99a6652ffef1d4e18fa01c0f7392f87b53aa489fcd00394ca582d8313ccbbe4537a403ece813e6d1a0dc5bb2e98681d408a2af6b967ad2bbfc9bf44727c8675578f6f643f76681c4c3cfda05cddd766889208c1f007d860aea5bc8dd0e4090d4e99f4749614608c612aabf58edbfe138aa4ab25a714cbf4b0449ac0b7d64651faf1493feb7a5f0faed21d4ce2d52916e18cd1c7269cde9b6bd36aa9817bfd2f94cb74568fd1adadfb4f8cc8e8b1be3c1a18f4950c9a1d474d10a5c29cf13b39fadc2766723a2177008e8976ec4aef5b1ee29db9eecca42b28119f41fe61cf83722940e38521130db780fa28a830a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16151);
 script_version("1.28");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2005-0043");
 script_bugtraq_id(12238);
 script_xref(name:"Secunia", value:"13804");
 script_xref(name:"APPLE-SA", value:"APPLE-SA-2005-01-11");

 script_name(english:"iTunes < 4.7.1");
 script_summary(english:"Check the version of iTunes");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",  value:
"The remote host is running a version of iTunes which is older than
version 4.7.1.  The remote version of this software is vulnerable
to a buffer overflow when it parses a malformed playlist file
(.m3u or .pls files).  A remote attacker could exploit this by
tricking a user into opening a maliciously crafted file, resulting
in arbitrary code execution." );
 # https://lists.apple.com/archives/security-announce/2005/Jan/msg00000.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eba3be11");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/119");
 script_set_attribute(attribute:"solution", value:"Upgrade to iTunes 4.7.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0043");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Apple ITunes 4.7 Playlist Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/01/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2024 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

cmd = GetBundleVersionCmd(file:"iTunes.app", path:"/Applications");

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

if ( ! buf ) exit(0);
if ( ! ereg(pattern:"^iTunes [0-9.]", string:buf) ) exit(0);
version = ereg_replace(pattern:"^iTunes ([0-9.]+),.*", string:buf, replace:"\1");
set_kb_item(name:"iTunes/Version", value:version);
if ( egrep(pattern:"iTunes 4\.([0-6]\..*|7|7\.0)$", string:buf) ) security_warning(0);
