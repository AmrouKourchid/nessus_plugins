#TRUSTED 57ac753bf510eacdf51a68b000dd2cc31fd13b793edc580bee1e6056c850648a9e164774c9d9a4de36a74e81dcd8563acd1db92450934510bbf50261a2bcb0a03a827d371b996bb7dc79f7be0a2948210af316cd2baa3728d3fe9f24f49b3545ada7aa04fa2e66870bca69f84378d3d49ce4372b48c1d1b58f8406dc8f9010a1228f9e7033a667e66c05ac403a77f7be1b81331a10b44ab543ba769871869e44dbf68de04c65f6bbc470c416b36966f976fcbeb75c98850e2d44d9c5ebfbe7b11f70d07c4ef643e7bf93f3e582dea45c350d7a35ec9e906c16f76d8144511048596ed85536b7647954a7f07dedcd4a2f6919b1410ff8abf51eae0dc843c901e738de70ef94f493d4425591db22efe658b97a876de48233d8b470352c538592f82a81d3ef9357fc84412d9ba140560f85a5389b092dcc2fa5465ed7f3b8fb2cf2ca3e7f736cf2e280be365d19c1f9396ea50bcf93a378331cfd4f3759660e1a276e5fc15e1209d9683e2a26568bc5ad3bc9bb1b4fa6ca58a072da6a7546c67d79ec6f5aa9232019327abb8b0c4d228c6b5aaf586f0a73bb5749bd15fb388d35e8a9212adbd21f282cbb0d175803807ade75bdc298c1f153b26e2986857bb7d9710c7f602a6743ebf0d469b98fe8d5185a71aeeedea253d24005e4564698f77531c4d0bfc0cfc6f5332e64c5f2239428113a095acfbde6af39f339887df4fea4b9
#TRUST-RSA-SHA256 9309e857c85f3cdb6e096edc566e0927566a55390f47986999dd87370f8c56d9512162b112388df10506536251829a9c8f25cc98a6a28909ee2464369f921ab7768c193a62815b440f84618acdb835247fd5edec693a5fcac4b273f19df56dc4516c05e2949fe39906327605a54ad1c7985c45a0031bb95716adc631ebb2dd959857677aafcae79eeaca197b9d60f61e1a42c3895b9d66e8d78525e647ef9a9de150085f9277a4ca7542b676c67f96f77c18f1ce16448b77bf2a485fb112556e99e38333ec6deb4d3e7a28fbe57fcd513e4bd71b883b67e64b68b239763a4a44e7ac37f7b5e48420660979c40d28bdad63016217ad0067fe705c3245ec201263b7a46d078039e0da61bc2da02557d8c3c673870d463c096a12e557973e633977d2f861dfd2afdd89b4415b39eda888ee356796b085b5bcfc3fe722a8bf67ad384a7e9275d9bd6d852ea68f6f090d8693c558dc0f6e8b815711c06e4e6a738cf60eac88ed9b93d9240d98320c4519efa0137d0d8b0ae623af0c34ab043a36521f79cafd3b0cc8498ba2ae4ab2c5cbc7e006354d72e044a835f976de73120282fa81a1aed9ac304441dd269e6023070ba88849c883226f50276a4b2b67978ce7eded073f4d8de8f0cfe93c8a20da7c10dea9f45574d64609605ce2a041154a74bf967c6b4f378b61fbb1ce10127eb5098b5dc8ef552a5ab3195bc6fe44c7e2d7c7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24234);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2007-0015");
  script_bugtraq_id(21829);

  script_name(english:"Mac OS X Security Update 2007-001");
  script_summary(english:"Check for the presence of the SecUpdate 2007-001");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.3 or 10.4 which
does not have Security Update 2007-001 applied.

This update fixes a flaw in QuickTime which may allow a rogue website to
execute arbitrary code on the remote host by exploiting an overflow in
the RTSP URL handler.");
  # https://landonf.bikemonkey.org/code/macosx/MOAB_Day_1.20070102060815.15950.zadder.local.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9741bacc");
  # http://lists.apple.com/archives/Security-announce/2007/Jan/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b953cc0");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2007-001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0015");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple QuickTime 7.1.3 RTSP URI Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.4");
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
 local_var buf, ret, soc;

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

# Look at the exact version of QuickTimeStreaming
cmd = GetBundleVersionCmd(file:"QuickTimeStreaming.component", path:"/System/Library/Quicktime");
buf = exec(cmd:cmd);
set_kb_item(name:"MacOSX/QuickTimeSteaming/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if (( int(version[0]) == 7 && int(version[1]) < 1 ) ||
    ( int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) < 3 ) ) {
	 security_warning( 0 );
	exit(0);
}
else if ( int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) == 3 )
{
 cmd = _GetBundleVersionCmd(file:"QuickTimeStreaming.component", path:"/System/Library/Quicktime", label:"SourceVersion");
 buf = exec(cmd:cmd);
 if ( int(buf) < 4650200 ) security_warning(0);
}

