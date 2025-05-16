#TRUSTED 82e1046102b2d7a9f880b76e22ec22d899b2b93e38ffb2be02abfbdc76a395d580a1352989269d666b1ce8a48a30d49159e13e9100151b90930c7f8c54545e3e08f202509e782189b8b400fba8f3f4f4c2cf838d6b714c2ee1457ffea5486f9515289f7e01d05b81d954ef28a8b4c552e85804bfbb81ace2b6e21326e5401d2c0b74f74c9b4c2ead2fe4b7070b1827b676af747b6081e3e66ab258a45465fc88edb7e487eadd28891b0e8a75bd91a6df97acf378c164553c755eb1629926a4a370a3b14c7bf5eba898a88f07c1fa5725f02aeeb92049d5ede5f4ae38dd1adc45136f985d4c2f4623f796bb39733dfe1775ec7f1815c26fdf0ce10d6129f767b60213c343cf7e01198d8e2dd7c915af5436507357fd7682605cec311928edf21d1903ff18bdc736d8cb3e0d707e274841fff87c9d0e6a811022ee640b6ede4535b1f176626b55b1408e0f98131f7afc7ed09b5ca0a1e00c5651a145c8b72bb1065441d85776b17b6c0c6ca09bf7714ab32f33ef74ef9e25cb106471b2f5c000dea12f37d5316601aa25f210e28061b117f40caf5b9b1ac81e9909f8ebde8ef1b65b44b9513495e8ced41ee6c628929d7ddd064a6f745ccc285977d76ad9c3fe7c0925dbfb8444cd4fafe1ee3dfe1f9273da5216b3655b5b63de11dfbcfc74682487474277950c571cceb15ac9d73a931eb87c2018151294fe44fdf9fa47d5fe8c
#TRUST-RSA-SHA256 4275067dff8ad4af10bbb4200bad185a23c769ca9373c9ada60bb6474c423f68429a1295f983c2eb0d257763b9e0c5bcb625269f88e064b1405090343fa726b4dbabd92ad14a9dcf6c4daff0e02fc01da25e27d92c89bd0b9787fffa634ef33e1faef71841cfd719731d9ddef32c781fe8923bd569dd9b8e7b64c1c0cb1abe3b06bd8b518f14f0dfe518394c6c44ae1a4f92c68ae355c44e97ea29a584f33ba2c2b94e79de342f228e7a90d5444aefba8db1ca10ac880b238d0212d394a37d3a78373e9a25c81d21481c98d1912bf4da340997458855dbaece2bea24d3303570b766f083b713ea5e08fd6d5d8ccdaa9f1ec0b796a9c024448108e0417355f0efc96815505f29e937dc617bc269a0b7165d5c6c9b460d41537ebb50245a7239cf0c530fa14125b3946e880262346c0480d7ac15bb29bc281a5d3a82d4aed73713de316632d5019b27978631598823d364e9e57edb412d51d8c07a7262233bea9076b24de5460ff397bb7ae47f1055c4223c9b1ca0dade7f556e4b8702dd8494a41cdc74457623bdc2d8fc561da584075892872afab5aaad3d68653865823e91856a307a3e3959080a967a1edddc3d2f1063a45c13a0eaa94bad9b47efb09e185ae0594214f1c0840439dc724db7add0c8cc9dd852709f9bcc0418ed64797981f837846918226866a81cd8d794e99af5c80438fcfd8f116ac36fa1c91057013f37
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19295);
 script_version("1.24");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2005-2196");
 script_bugtraq_id(14321);

 script_name(english:"Airport < 4.2");
 script_summary(english:"Check for the version of Mac OS X");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X which contains an
Airport driver with an automatic network association vulnerability, that
may cause a computer to connect to potentially malicious networks
without notifying the end-user.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/TA23400");
 script_set_attribute(attribute:"solution", value:"Upgrade to Airport 4.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-2196");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/25");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2005-2024 Tenable Network Security, Inc.");

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
os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) exit(0);

cmd = GetBundleVersionCmd(file:"AirPort Admin Utility.app", path:"/Applications/Utilities");

if ( !ereg(pattern:"Mac OS X 10\.(3|4\.[012]([^0-9]|$))", string:os) ) exit(0);

if ( islocalhost() )
{
 buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
}
else
{
 ret = info_connect();
 if ( ! ret ) exit(0);
 buf = info_send_cmd(cmd:cmd);
 if (info_t == INFO_SSH)
   ssh_close_connection();
}


if ( buf && ereg(pattern:"^([0-3]\.|4\.[01](\..*)?)", string:buf) ) security_warning(0);
