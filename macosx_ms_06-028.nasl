#TRUSTED 7d1fdca45ad7ac0fd65af9d2de4613edd1f86cf8d823c84d468f84305047fd5118944cdc2b4fe3d535e5ba239ec701c06ffed38494fb1778d2d7bb19f08a6254d61ff9e9255f16b57e0380743128418728f8546f002e1de802e51a1bce7adcfaad597b453044131f7e4dd99aa15ad61c1133d39eb65d8d9d4089cc0e2736f7c1c65ce87a597e36a2f66e84aa57ed25ef1f581bd2e3e2e4b58e161baa9f481acd50c717076af6191bf0235891a98d27b82b47eb508d1bef2878ae1a9b3115f38247087b36ed6d28354d96e15cf2494a7de2602e20b1804c78f339291a5e28386a2b79e1d57c33f120cb3540ad9a87041e3908e17df190187529c922ab266939c5d7bba9ca73f4276c02f2840e863df810b60d47778d53b232cee1e049c22651eb107449f7e131078a979bfd65106afc3483066541503ca139f1bbe55e9249b599fff688dbb67074e7edc1fef9e96ebcf9b850358a523cb53bc7b2aa377e24dccd48b81c120779ef5a463528b115dd83e2ade5a5d40e0e50c430ddd49f97a7db6c06a25f1a10074b974a6748653d273ecac5d7195a49d9d8e0e2e2a1c41946fe2b67ee44adf6b9869c52debb33a809b8789764d52ad19763047074e9e60bb8b7b69919eb7ba415ca1085687149769015253362d25abd66bc4995521520a0466a60c1282dffa3e7bce59f9337a5735367aee862adde7ba6419c3a2cc75287a60143
#TRUST-RSA-SHA256 912dfd97e9163e34a25a4690f74a889563253fd85d0f8b3485ab8488097a215ee185a5616fa568ca1084ac66f5cdab8ec97359a6ff4f0ca2c9a6ac122b722e30bf9f53a04f745561c9725c49eb884b5712ad2d363d9ad784cdb60ca5c994394ba175559cd361b4e047e524a48c82bf3dbd229d0abe1186b082cdb49e710757cf2906dbcaaf9840786290f746cac91c3c464389ea9c72de5672036eeeeed469cf7955ad13e9ad15399b01a664fbccecfcc202bdf531c16019b5a2bedb00309cf0b660735bc1ee408e0e325be4ed5a682a2db0c1cc478a93aed0ff1c3112f1de19d0a58dacfbc6b43ab3f12d3d6ff8fc93aae02523e80e2197100078c544dfe339a584afb28cf7a5e5600466f05d0eede617769e201d5e5f4f1f8838d352d0ee2cd100687b13628961c45fd4741f53051c52d09564d5570e2f2b012a714ef06436e0e49ec2d7c0422f20c7d5b36d7684f4147fd0d8440bdd7dce35c2a1214f004ecb6e05797e1f3ef195af5d2c405e5d961b52716d5f8d17df12028b001a9b6ad51d260604ed53ac1a36107c2941d95a94aaddf2fb879de3b451942a50680397947e5eb9fac8d1b999f4ddf7eb9cc14533b0e0293ba983e0bbf226e7f0312986c348a93ecd66f9e865aa012aee8ef586b2c9e5e51e2387618291230321ac655a4d67b13baf434d92ec754750cbee2311ee6ccb0aa1d29b0feed7c4719979b6332b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21724);
 script_version("1.31");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2006-0022");
 script_bugtraq_id (18382);
 script_xref(name:"MSFT", value:"MS06-028");
 script_xref(name:"MSKB", value:"916768");

 script_name(english:"MS06-028: Vulnerability in Microsoft PowerPoint Could Allow Remote Code Execution (916768) (Mac OS X)");
 script_summary(english:"Check for PowerPoint 2004 and X");

 script_set_attribute(
  attribute:"synopsis",
  value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is running a version of Microsoft PowerPoint that may
allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with PowerPoint.  A
vulnerability in the font parsing handler would then result in code
execution."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-028");
 script_set_attribute(
  attribute:"solution",
  value:
"Microsoft has released a set of patches for PowerPoint X and 2004 for
Mac OS X."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-0022");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2001:sr1:mac_os");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");

 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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
  off2004 = GetCarbonVersionCmd(file:"Microsoft PowerPoint", path:"/Applications/Microsoft Office 2004");
  offX    = GetCarbonVersionCmd(file:"Microsoft PowerPoint", path:"/Applications/Microsoft Office X");

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
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_hole(0);
	  else
          # < 11.2.4
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 4 ) ) ) security_hole(0);
	}
}
