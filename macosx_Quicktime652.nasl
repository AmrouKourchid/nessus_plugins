#TRUSTED 84f5add801d48ce937be21dbeb9b409a3dc1eb2b81d7fe88cf60d02a4124b2568ffaeefb826b0e5099237646cc476b0a3c3e3b27c634031b86add1186d73d4acc83e22fa2b3e2b4acc46d3bef6980ebcacf7e6f7f1fefe035860a76b28780e45dfd6266ba5e71fc05b9ed2c0d6f824c087efc1badd790eb39be6bc9a68b85f7610e6a8b6268a830851fcc7d1c6bb696f92ce0f697fa3e86cc432159c4b332f0c588d1bc21d13add4d3010960cc6fe20d57cfc235b641fbbf4c18156daf497d15b3635095fc734a4f60aa55629de315e314b7de82d4f964e76db5d93c6bd2116c0f918ee5dcc87925462699bc890f3c31e747159fa1bbf4a4dd744163b1bd32611dbe1f7f5c491d04f19597ea1a3aacd9508b7f45d09e69637b9c3bd1324a8c5cadc0822bf01d12878de0d7d4d0ba3dfa1b8c93543b2cd5becb67c225e2b49c85d798bdf2af9c411d83939bcd3ca366add66927b1df52f85f18d8e6d1449cfcb393b6d6b3be6106de607bab967b0ea738219e2486d5670c8d88f4c126afab5336d6d603bb28fd2c4962ef35d4da60767572e31406141a895376c9f6bf98de01c0a01dd37ba8bd5e1c23cf30ee6251b6ca50abce1d0f690f8712af8876660a682f97970ba995747693f34a4324f19a5a65cb7379d2e1386cc8b234cfe201d8be55a21d94143b27079969cab59c5b9cf20c70aec6fa48811fdb22c2501700424129
#TRUST-RSA-SHA256 a34c59266db0afe711314f0465d841358b1f33d172a65eabe328fef03073266e430ae333bc5a05c7833e379eca48e3576678cc604496090d567e369c621f5774d52daf5e71acf0bec95eb257a360c060140e2c290a9105c556b15bb21552175012e5c5713bbefa109c81055bea8b1f57667574fd6715f7474bd317beecd39bcf1f26e54feba89ee0ccaa618cb85c9559ec9a060b01d1c96e89f20ba5b61cd9f6aaf5e8ef73bbd34b391960669f67c64606d444adb8289ef7f64435f63a08405461b5ca7dc766af581742639cf25ff2a54e2d191a0cc238b1bf3e4088af28de40ebfcaebaf6a7e760c94073df8a152109b6b672e3d4623513982365c441e5897e67b285c6a1d9cb380dd89323b3dfb796c3102afc9328461e25a9736b71b73d1fa96e4388b81a9ca3e52cc6455674a47e023d5248dc64116888f927c48ff9413ed92c354e89b32c7249ebd8b5fd7f1cc443b2a455d55bbdb392dc72fefcb9dc95acd3552bb272d9149ed3343d13a8166defc9e90b992c4eca1e5651627f970c983f298f1c794124e1ad50c8e6ccc5e077d49447304a5bba4968691a971f08dbd639991cf8a0c28031c4d399a533f6a1c7500df2ee42520ad27fb5ba10899253eccad4e5f9a14ed5771a0253085a2e21304699260e71fb77607da5fc24989700bdb8d15485c283805e2d3d2b0e8bf05989bdb404c4c7a8175c7d2d1c1397e785e8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15573);
 script_version("1.29");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2004-0926");
 script_bugtraq_id(11322);
 script_xref(name:"Secunia", value:"13005");

 script_name(english:"Quicktime < 6.5.2");
 script_summary(english:"Check for Quicktime 6.5.2");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Quicktime that is
older than Quicktime 6.5.2.

The remote version of this software reportedly fails to check bounds
properly when decoding BMP images, leading to a heap overflow.

If a remote attacker can trick a user into opening a maliciously
crafted BMP file using the affected application, this issue could be
leveraged to execute arbitrary code on the affected host.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1646");
 # http://lists.apple.com/archives/security-announce/2004/Oct/msg00001.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a09c212");
 script_set_attribute(attribute:"solution", value:"Upgrade to Quicktime 6.5.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-0926");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/10/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/27");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
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

cmd = GetBundleVersionCmd(file:"QuickTimeMPEG.component", path:"/System/Library/Quicktime");

if ( islocalhost() )
 buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
else
{
 ret = info_connect();
 if ( !ret ) exit(0);
 buf = info_send_cmd(cmd:cmd);
 if (info_t == INFO_SSH)
   ssh_close_connection();
}

if ( buf !~ "^[0-9]" ) exit(0);

buf = chomp(buf);

set_kb_item(name:"MacOSX/QuickTime/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if ( int(version[0]) < 6 ||
    ( int(version[0]) == 6 && int(version[1]) < 5 ) ||
    ( int(version[0]) == 6 && int(version[1]) == 5 && int(version[2]) < 2 ) ) security_warning ( 0 );
