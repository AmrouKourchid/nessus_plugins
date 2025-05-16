#TRUSTED 69344c0bfee1881f3a736db161fc6e51406e125a48cbeed9ba83ee050f80d138d27a95729a72a5ae6032112d10007c4df03c1ae8aff5f0542e94980c684ee6e34b1cba6bcc5f7fbffd528c8a9a417d98037656777241f750a1f7f400c996e9cd970908ed88c7fc9d5bcca8d784e387d2def3210bd111906d2c254f06bd63df6b8e9c4a1eb5805cfceba9c274dbd84031408ee9f436d8eb8b6f8b2d51e8c57cad43e674f5a5697d69c84c4083bb420980cf2a792d5bb87b05b2b512d0094ae00c23a0f1afafbbc47687657d867c5b1f7686f0641b6956d7f0e71533539acedc6e2d91b9ef017d4e6187c7467c387e18019eab1931fdf652664243ed56247ebfbbabfe637556cc0bb5f915bbe60f241bbfa6225b165c28a6ba18e88e65491a2ee3a7763021640ccf6e09f7474fe259764999382786cc03acea95841323bd070c35c218852a47c3f64844fdc4b03ed05a45a9d194ed1e112fafb52dd35290a343df316e6951c7f9dd869a1f78d12c5b481db866e0d5174786086096a3df0e38b935bfcd0e6136479901fd6b86abfb5e6f40ac97ea82dd630a3d3963e1925751b5ba9ba0d743bd331a05bfc3d86872401e651362823b807eccd3eba43cffa71521d5c3286125c01f5e804f8cf11923517b62470e37884c99e2f13a80e2167fa45a557e0642f94e9c40bce61d768e3e1dc76606bda78921f712904f8a2199325801c5
#TRUST-RSA-SHA256 5726fb836d84e7aa20c46bf2e929ba9d72cca02229a3cf4a2e1c82726c01f38d8dd1fb5e8fc80d6ab18f6f3914cdf0217d6e16a927480caca07f2e81d332b605989870cf69b0bad31789ae9504c895e9ec9fabcb07441de2829d3bfd16c6340c6bfdb4e34f057cbd4268bad2bcc2a68b3d1c9fc150964a28e36d054dc7d875743db1f8c0bce2ac0957aa93dece8b2f5cb5617b470a525e4039170b7d455584b581e2cb1d8cf3b982c85178baa5c78c7531ef006f7f15c9a19e343606f8040ae60fd8b6175d8cb1726545b5bef6293b4d19c7da5b2b48cedbd99825b953bfb5fb6165f06b8d8c9b47ec3c7f3915c83188f2a621fb564c31ddf3a2087bdf0b1efcec29203c2b1ecd52faefd9ed5150446d3195dbf2205149f424156683e1c8a1c67fa7c9a103efb76c7ced36fffc7d204d8708ed815ef978f459ffab8b093f73bdc56e7b575246da79abb255ab33038d2c8752280d554fbbf99908e6a110369a8470e3556484270822d5198943ba062a1f776e250219f6f3cf4543984dc81e1415f83ed55f60b268ec67431fb0c09d6b7a4b9c9ea4f117092bdda82aaa5c471c642f45c3a72c0a025935039e58074345b43531727b01387e54c9186e88dd73dcef0689d2c10ed597337a44f0acd2db171ca9e377d6747ca0317167f7a4d20a0ba51712233adfad31094ce547b24cbe418d3b1a1b59b70ef2700584f7dbe2663f80
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22539);
 script_version("1.29");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id(
  # "CVE-2006-3435",
  "CVE-2006-3876",
  "CVE-2006-3877",
  "CVE-2006-4694",
  "CVE-2006-2387",
  "CVE-2006-3431",
  "CVE-2006-3867",
  "CVE-2006-3875",
  "CVE-2006-3647",
  # "CVE-2006-3651",
  # "CVE-2006-4534",
  "CVE-2006-4693",
  "CVE-2006-3434",
  "CVE-2006-3650",
  "CVE-2006-3864"
  # "CVE-2006-3868"
 );
 script_bugtraq_id(
  18872,
  20226,
  20322,
  20325,
  20341,
  20344,
  20345,
  20382,
  20383,
  20384,
  20391
 );
 script_xref(name:"MSFT", value:"MS06-058");
 script_xref(name:"MSFT", value:"MS06-059");
 script_xref(name:"MSFT", value:"MS06-060");
 script_xref(name:"MSFT", value:"MS06-062");
 script_xref(name:"MSKB", value:"924163");
 script_xref(name:"MSKB", value:"924164");
 script_xref(name:"MSKB", value:"924554");
 script_xref(name:"MSKB", value:"922581");

 script_name(english:"MS06-058 / MS06-059 / MS06-0060 / MS06-062: Vulnerabilities in Microsoft Office Allow Remote Code Execution (924163 / 924164 / 924554 / 922581) (Mac OS X)");
 script_summary(english:"Check for Office 2004 and X");

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
the remote computer and have it open it with Microsoft Word, Excel,
PowerPoint or another Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-058");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-059");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-060");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-062");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-4694");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/11");

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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
  offX    = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office X/Office");

  if ( ! islocalhost() )
  {
   ret = info_connect();
   if ( ! ret ) exit(0);
   buf = info_send_cmd(cmd:off2004);
   if ( buf !~ "^11" ) buf = info_send_cmd(cmd:offX);
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
	  # < 10.1.8
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 8 ) ) )  security_hole(0);
	  else
          # < 11.3.0
	  if ( int(vers[0]) == 11 && int(vers[1]) < 3  ) security_hole(0);
	}
}
