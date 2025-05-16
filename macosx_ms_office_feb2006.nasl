#TRUSTED 20e050e3d0b050537b0d4b2d2230870b1bb9ba02a43b872adbb849db46859592c85feff5fd95080f9bcd69aa04deff7bdc719d339b4a4fec9062bc23417e48d81c8a7557bfa144e09c46ab9d31184bf99927241bd569a90aad70964682d3ba8d1d6731653ae6dc192297e5b2386693d2f5a19ad5bc3414463fdc0d353155f51298075cf3a5daae7843d35adca590501b3e40547996e2ae7ed7f156aa145e2823322339e323ddc2bfc322fc78173b198e7484cfffc0ac362407ba55878ac2f9a7fb2a68c3072cb8ba2d436ef5233a7ff94879d1b9317dc60516bc2545f04c1a897e5e921a4ed1eb16feedafea5febb37fb638a8ca8262627f9185971e0c65649207242808394eeb8b378563621caba8f0e59693fd60e0bfd782732c9d90d74089dac379449915ef99729237f1b5bb0e6734844c45e48383c2b695f79aaa2cfa38fc19c156cc5dca2d62794952e9fb6f458b7e386b125ff180a14eaa5d1b14e53ea621edcab6bc7595ca9433757adbf7b7854aee54f04fd6a5891eb0b4ba8c4ee125027ef7e1ae4d48e0d4b6b8887ac7c2ba6d4b8b5d74a648eef5d5b431a6d6887a1ef0421ee0c17400c60bb24f3c9d5481496d30108c6a6b66e83fe6cb6632489dc5994b41ae33559e1e5c902ba3b9b782795c5b90a695c6a040bfb2f90b47a0f189d6c376aa68cf86e2784790dffc60a08840767f0701f3172510dcc925d6f7
#TRUST-RSA-SHA256 a01c1392c7a3b1f9d1cf768da5aadfab9636c9b9c4ec9d899a4e7c21e88a88239b0f84fdf1bdf1d2cd77d56658561595cefa6d3bdd4a9baf8039a397ebfe055d1307fdfb127934be2008bdf1264b5488dadc2955b2868b84c90bbe5dcd46855a38c04082060e822e0cc0f9858eb31add1661db747d5d152cdda8a2dae3b2b39cccf8eac3aa36d44dadbe94bd0f5076227bcbc093ca571be8d7ce05ee78f9e6ad444f747c4b299244d15b46aed3c65cee942c04df1f64e0fa3dd4ae6579fb35251868d9b7e01b27aba039b2a8af128447e9472283470c429f8da55308ecce7bbb711eadf2b81f587c383fec563cea12865da9e7433cbe4ac011b7b473a061047f481a9b616d90dbf8cd947a3124e7701f1fc8fe758885c377534775dcf90d009e7e244e9944034a554f4ff6a82b9db658811f193def0084f1908b22ca91a1455f1f8c448ea23ef76330efa420768a445ad17d54f8f10346b8f56244eca1f9707b85d84f9b5129a1c6e76002066ed209cc1fa8781a9de44cd51402543df40a4a549cdf394779cd2a5a88ac5043bace49c4ebec6fcf737ba3acb374e8e5459095c2d66f83bfb4d6b7558ce2c4e78308080cbe538bc12a8f77e44455f69547d5dc886fab5ca18c78d7bac023bd4cc353915ec11ba1be1a39d5ac80de77bb17ffa7eb3673af27c298f7ff18bc1ffe307a16d759fc19cd573adbf3f4246bcfc9d2e05d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24328);
 script_version("1.30");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id(
  "CVE-2006-3877",
  "CVE-2006-5994",
  "CVE-2006-6456",
  "CVE-2006-6561",
  "CVE-2007-0208",
  "CVE-2007-0209",
  "CVE-2007-0515",
  "CVE-2007-0671"
 );
 script_bugtraq_id(20325, 21451, 21518, 21589, 22225, 22383, 22477, 22482);
 script_xref(name:"MSFT", value:"MS07-014");
 script_xref(name:"MSFT", value:"MS07-015");
 script_xref(name:"MSKB", value:"929434");
 script_xref(name:"MSKB", value:"932554");

 script_name(english:"MS07-014 / MS07-015: Vulnerabilities in Microsoft Word and Office Could Allow Remote Code Execution (929434 / 932554) (Mac OS X)");
 script_summary(english:"Checks version of Word 2004");

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
the remote computer and have it open it with Microsoft Word or another
Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-014");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-015");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0671");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Word", path:"/Applications/Microsoft Office 2004");
  if ( ! islocalhost() )
  {
   ret = info_connect();
   if ( ! ret ) exit(0);
   buf = info_send_cmd(cmd:off2004);
   if (info_t == INFO_SSH)
     ssh_close_connection();
  }
  else
  buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", off2004));


 if ( buf =~ "^11\." )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
          # < 11.3.4
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 3  || ( int(vers[1]) == 3 && int(vers[2]) < 4 ) ) ) security_hole(0);
	}
}
