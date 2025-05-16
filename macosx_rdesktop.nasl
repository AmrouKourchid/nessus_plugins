#TRUSTED 117cfb236d6a15a89cc7301a806508b0ee100035ec6d1c2410253a202e64daa000a6b1e319708d776447eda670454548419034430b9ac534e061ee0e1099ca5795e826fe23e558a87c2ebb5dfd0eb4fb3b32c939dfe70fb68e09161ae9b90fea14e27ebc9ce667e93c8083f1a76c6fbd7d76536a7d8992e3c120282c26d2ae9a9ccecd509308431efb9b57c7e817e7810bf8aa81a78d4e734b8f7ff51fd080af92a531ccd2420bfb0b92a8def6bdcfd56fbdfcc8c7d3fe0c4afb61331f6fdfd428bc6653caed59d1972d6a571edcc27b4bbe6463137257869bf477d233a13725dfbaefaffffbb08ff165cb8cd1b69a81652415192cc9b6a76fcf24560f5f32f618990d4d22f0298ceb20f8de9a4a1fd221b1b45dc7847d2b6b78fd737c095cf3fe53165754697aa38806898c7e011ef233c61729c9eb6ea67dc4adb9efe7c3bb74bcaccc163dba0f4ff41c2e590ea135a96bb9a43df0ce8a0a735680ea5c560946aac9bec42bd93e6ea20e8c054af37d2d29d3f45ac050625cdf81a8b1b21091f7910a3a51df3827e9712519dd48df222f6cdf0bb05836a8ddef28e2530691f2e3920a51f2d1557ef4856c12868b2f7aef1156ff27538caa15bb5d86ffc92c3e44fa47f3d22131251d9915de3cb48b97089fd26179a7a9738db5f828aad6eea386cfb03112e36f8024bdc011e8425f74f7db07f6e5798837748b8ddaa22676da
#TRUST-RSA-SHA256 7329deca9218ba5ff78e6953ab1328e20dc454a7d69d00aefeffa64830b88878a389e01c8df4963bd943ac5d8476c1403608e7c837bfc5f7f1bd95cea2370458b1a10d00ed61778e2cf99216ffda6c8a25f1920371d81370d49fe64b9296d25743b145eecd222eacb803676d1f74f5b40d0d2a6aff78935394258aef4a8eed957c8e0b93fc9c112eddd37f0f9cb1d6ab8b2f19b8d3d34345b8a36d23a066326d3d9405f3d990811747d8bad138d8711427a09ea9669e5c538909fd753c9c10b32048ef0f9b241edaac2c8b76e8a282ef9af0f48896f78cfc041867452c2b604633606bfd18a702edcf95f955acc48d5e99266f365c6b93d03d609b4ee0cd28100fa440c4c42e9deca2739efcd01518c32245554eab67593b9f2b5210d7913625497ed01dd99a2c043837828773fae3eb1ebfe28077966302329bff792ca921b726796b2ec345f1acf296675fb6b87b75ddc8ff47f867998e7452422a9fa967a8e1bad9122d709663500ece6ecd9793714d1c5ddacc560e4665b7e3f1ef85c1ed392f2edbfde0cf552ae65b783c7125a58f4938541a836c90362062930d36756a1f86b4550eefbd3a661535cbdae01e4140e6ad34dc5609ca64854e8da7a48ada03dff7cdd037a201a20f9717c29352bf368013f96ed6b03c53b2d6c72b0d16680ec94ff7879145c9473a9e3e4a531a23db337c88730f494c982c5d584111052a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40563);
 script_version("1.25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2009-1133", "CVE-2009-1929");
 script_bugtraq_id(35971, 35973);
 script_xref(name:"IAVA", value:"2009-A-0071-S");
 script_xref(name:"MSFT", value:"MS09-044");
 script_xref(name:"MSKB", value:"974283");

 script_name(english:"MS09-044: Vulnerabilities in Remote Desktop Connection Could Allow Remote Code Execution (Mac OS X)");
 script_summary(english:"Check for Remote Desktop Connection for Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Remote Desktop Connection.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Remote Desktop client that
contains several vulnerabilities that may allow an attacker to execute
arbitrary code on the remote host.

To exploit these vulnerabilities, an attacker would need to trick a
user of the remote host into connecting to a rogue RDP server.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-044");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Remote Desktop Client for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1929");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:remote_desktop_client");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  file    = GetBundleVersionCmd(file:"Remote Desktop Connection.app", path:"/Applications");
  file    = ereg_replace(pattern:"version\.plist", replace:"Info.plist", string:file);
  if ( ! islocalhost() )
  {
   ret = info_connect();
   if ( ! ret ) exit(0);
   buf = info_send_cmd(cmd:file);
   if (info_t == INFO_SSH)
     ssh_close_connection();
  }
  else
  {
  buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", file));
  }

 if ( buf =~ "^2" )
 {
  v = split(buf, sep:'.', keep:FALSE);
  if ( int(v[0]) == 2 && int(v[1]) == 0 && int(v[2]) == 0 )
	security_hole(port:0);
 }
}
