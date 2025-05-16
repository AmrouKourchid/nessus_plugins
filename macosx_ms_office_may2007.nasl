#TRUSTED 0ff5209f0f79f27f06d06640fa9eaf2a1d0e8ef86bef96d81dd1c4163ab95b14e826b75ffb0aa843fb24c0d41c88e5961e6f10938f3225799815e02a1e6a774e2ef965aeab926c6f1c78debbf12e70fe94aa0286403849c0f41cbf3afd3ee72252a19613ff55c62b1566a088958fb8fd7438c9827f73e4c7601f2ffcf94da9a2c808271e5b6e66ff4c546d9e3abbea9d5018e00af34c5814943e731a368d651eb32832d7986ae2185e75e44141fa7c26883021324913eacbb4f02510f156065158f4f580d881f3b2d3e04e15add12ed8f95e0b39eeedbac2d5b9a29720f04f4ee8e4e393b44b9f9a952cde1d7ab7a89ea0eced452ef016fa129717da56818c2f052a87265343a3f7977be381ff0897f9b1fc92cf7ab886572022867ef7d70c9f3edfbd1f6633f4a758d6870b4b33ba7105dd67bc1c21037846e262504049080fec8deebdb237eb5349fa5ffec80cdad74a9fa8cc92eff9d85c3e038e93c19f2665a947aaf435c236078bd5edfaf98e4f30a4f7d360b56eb16ddef205f317c531af39eb4155149df583c7bc652243d40d7d6bc4e3935bba54028beafba2135b4656905abef96fecdf6dc524bd93b0dbb515951a60198a730730f5474e99def371537f29d9595c6a5765835cea1cdf5b3b2b54d884c76a3d9aee1a269e47c6bd346693306580de7039a28372ee9e35d92b18087c810204619c1f60bbeec0017d23
#TRUST-RSA-SHA256 38839397556749d1adefd9430060bdadaa6bc95a5cac6d53c6c603e4bbd2b0dcc93c3743f9393341dc9671534403cc2073a59275eafda9715e485e9c8dab02ab9a34593d4d2224f76e7c4387deb89033f9a0da414513786f61835e2e9593df86fa9a5529faccf1cc4fd44f2aa81a8bae6e6ddef9960a4479b5d3320399ef2949743f064a93106fb4cf2adf2ad593cc6b7ffb39d09e1d1141693fc3d7364ed1a63281553effbf177dd011953c1853179b92aabfa95330a8ae5c5cd69ce75255a7edf3dc1589a501d06c79e2206a1e6dfe182e60eccaae2efa1ecab63d337da2851666cc0f569d3952d97f1a075009de3a0d7cdb59c40f7148456047b1c3067bbcfdec806f6673364cc956750d327743109ad2c77e0a005f2916395263847f3bd745610048fd7e210fe83b84641962de5515be57557ddf9e1210f7c5ec003cdf4d269c7f8b8b9392c9539850904f52a7efb87841f659d568c83914262ec3d82a6cd32b72518fc048d136fe61b76a2a5dde26937e5d4fc0905a11919ba86e8680fab47c12a567faf6d1f02422bf9a24097ea3c0fe9829229a25d94b81efc0486c7f7c846a02db7e8f819f510f964f12adbd84fba7ba26437c87332644feaf16a0697db6ca57bd384172a9369d47642d90d8b03784f407f5b11bc6c5eb2438f2e211309f450e81bc44dc317b3b94347e6ecef9cbef3c47981b3faa93f5b630f11e8d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25173);
 script_version("1.34");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id(
  "CVE-2007-0035",
  "CVE-2007-0215",
  # "CVE-2007-0870",    Microsoft Office 2004 for Mac not impacted
  "CVE-2007-1202",
  "CVE-2007-1203",
  "CVE-2007-1214",
  "CVE-2007-1747"
 );
 script_bugtraq_id(23760, 23779, 23780, 23804, 23826, 23836);
 script_xref(name:"MSFT", value:"MS07-023");
 script_xref(name:"MSFT", value:"MS07-024");
 script_xref(name:"MSFT", value:"MS07-025");
 script_xref(name:"MSKB", value:"934232");
 script_xref(name:"MSKB", value:"934233");
 script_xref(name:"MSKB", value:"934873");

 script_name(english:"MS07-023 / MS07-024 / MS07-025: Vulnerabilities in Microsoft Office Allow Remote Code Execution (934233 / 934232 / 934873) (Mac OS X)");
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
the remote computer and have him open it with Microsoft Word, Excel or
another Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-023");

 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-024");

 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-025");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1747");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/09");

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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");

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
	  if ( (int(vers[0]) == 11 && int(vers[1]) < 3)  ||
               (int(vers[0]) == 11 && int(vers[1]) == 3 && int(vers[2]) < 5 ) ) security_hole(0);
	}
}
