#TRUSTED 89078a10f69f9e0a9157894619202b1eeb8360cf5dbba954ed200e98dbad16c3708f377bc900d7b92f081b2e3daeadce716915404164ca7eb0d252bc48a43fd56f9a0d6240aab6006e9a2fbc60e3f6445f7b6b347b66068818e47b68098bba11137ee0a8748ceed99f125699b1c47f969b9cfc6c30e6d7259e6759837046fcfc773bcc1cd2c8d0281a4a591fa090ca43001ecd1dbf9407ca58d162be80816247249021c055c6ef2d3c220f04964568dc2d686bd278ced9309836ce1373a0ce1455094690feb3db8326c6bcfb0b757a27cd37fad23a62326578fa6fe78c2d8fa73e1cbb51e44b379f8f5a4e3782b91c60912315c351b5129dc3c3c421c0861d82946f579bb726d87cad70ce38ffa28a72ea4547b2c0cb529a6f8bb001ca13c19c656f215110553b97c05bf93258e689a8c336534fbb37447882e471d6adefd7281045b24631326051b8ec6425abd1187b7022de009cad066aa098309be278f988670a30ea1e8c6196a68b3b3091988ffc812e6fab9c2ee2f41acce8e6a37d4ad4b6fcdfb30dcac1887ab53f38e8eb45564bfd04d26d3a4285307d6bcd1e8c4699d2cc49805a6dd2580461641c705c17938046b4fc2bf72f33e962a31ef1933b7bfc5f494937c286711570fe8fe1c860e307fb8367d9830a2a5ed483aa82c92c1106fd192054b6b04684658da0c8e2851cdeaad7062e33adddcc40567a98df8df4
#TRUST-RSA-SHA256 46e926b42dbb0da38ac37fa22cc1edb619efcf0b47d69aa480476cdac80bde5bed904455703f2b78db8b41cc54a5018ba5f548698dc94b1fbc08871593fc970f7e6e308cd4425ca094e28815e9efc690bca8c7149d3a245636f919cbece631d53a3ab20b8be30577931d5e19bb8942b11fe181ac45900c51c0bb59dccb9aae522857e6e53b1c7666a97962a441f8d72c7eeed82b9ae1e5cae617c5050598aa69ff9fe9acf7b8c894f086ba6e5a511717ec6ed94c631443ca2ba681bf3b93e1be951f813d7865b0929d74bfb84290d6eb3667c6c9a5e5f82498e7c7c2d998d1eeb2eb9629e0adade946feb23bcc879cb55fcb5d96bf67a8d2277c3d4fea5952038a084c5eb575b1a0f2e0a973af3d2a294669466c7ec2e335b2575cdfbbcca4673bdeb7627de18851fe34df535c2a3db00fd54404301882320c464ba22065228c1cdde0a51c3cd51e1c2ee7cf5c9d180ba204b52071e17cd75a5c0f3f26871559870302e89a9e7436c20b6d6b5a9c6ad89d519bf81feb26b0eeb911e8818669e85152825c5751978dd565e1bf6b8d7178bfa7576491591fc4838028bfa013a7bd6e037cb786753cf2d858fe2c6f11f6510328541908257340f586d1910f8cc9979901722b0c5da227d15b6c6249b99b6c6d4b80330b8ee0f8116850e59887ae2d763151811ade607192b1c2716acd8c4dcc3d6527d78c38eef0181a90d4f51973
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15786);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2004-1021");
 script_bugtraq_id(11728);
 script_xref(name:"Secunia", value:"13277");

 script_name(english:"iCal < 1.5.4");
 script_summary(english:"Check for iCal 1.5.4");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute( attribute:"description",  value:
"The remote host is running a version of iCal which is older than
version 1.5.4.  Such versions have an arbitrary command execution
vulnerability.  A remote attacker could exploit this by tricking a user
into opening or importing a new iCal calendar.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd087f47");
 script_set_attribute(attribute:"solution", value:"Upgrade to iCal 1.5.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-1021");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/11/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/22");

 script_set_attribute(attribute:"plugin_type", value:"local");
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


cmd = GetBundleVersionCmd(file:"iCal.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
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
 if ( buf && ereg(pattern:"^(1\.[0-4]\.|1\.5\.[0-3]([^0-9]|$))", string:buf) ) security_warning (0);
}
