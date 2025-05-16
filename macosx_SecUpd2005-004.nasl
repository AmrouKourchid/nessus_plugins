#TRUSTED 04ae01f8664c2d409e04701b701ed3c24140df6e959f8ef5eeeca88ff7906866e725bb72c2ce79f04e73709c591ce1a0fa6d1cdcc35beb4af6d4c2b0ca38643b8c18745133d6821cdd1673ac819d32b0c016893f83c6679f4123c82e641af8904fdbffa042750c5639bc60d9f11ed921a07851da676417d8fdb76c89c1aef0f63aedcdb393a3bf207fc76a5052cc9bc14970e624c872efc03fcd75d420d693ec3c3f621e170a6328fc3e02760b15860a60d6c22e1ce62572ae4c1ebac264ca172452e5c7c86abe52c34bb19b57bff81b8d40688fcd1dcb4b62f8a5c71b790313ff1e5f734374dbda851ca3a6f03b3fb966832f184986665768e97497ee1647ff31ed53b285c9fd9eea83b9e7c88e0f1e8c550cc74e82ed088ad27024e3de97ef94fdfad8c149d20d370e5952765da0bd79113c694a819fd298488f6544e377e8785dc029882f29b96495bb1f0c19627cdad0d6f5c9f2bd9e0418e3b4c5e8ca713f0c0a25157bd83e663cec88d6e32c0aa1055b64ae99892cbc53a306cbb333c442bc3a6dd9c5712cf6abc2d6851d1bb8d6d0d68373ba6afe442882128b8c94f838a3f5da5eb478c9949ec98eab91e30d3dfeb01e0292d673a13716a3065097a40a217745026766250a27b973bc5d6a1ae5c502354bffa9eb94ead611099c6736db5eb96b978a05c6443a3a46e161e8565d9582ead192c4f4aa2f9674c1f562cc
#TRUST-RSA-SHA256 06c25fbe2fd394961e4fe9842157a868d95f32a8081f521f770e238d98b401ec66763f675ef300f8e8535873a30c432d41de3f05bcbf277fdb80791f835e256aa7217fd7253befec1c9402929f9a7569832ff29b22a48baf1a6a502dd4f01d23b0cb6f9813d4bbc66a42b0b3bfd7b1acc844c62173420941f785df5c69270f6aea17fac79db0cb77778f74a75a85d029c563c44733588ef197fb370731492f6f2915a5911a576ed470c3ab6366cbd12744610a20bab1004f99b837d9641c25c8a7c9a93e554adc4626ddd3daf7bd71fc5716c44b5a6e109de3618ec848c4682062190e42937b886da10a4f9e422c3b82ef9e0e26bb3142b928491e11186b88be15de2ca66c08a32203975c8df09dab7866f4081e0eba463c743d8a985a6a2cc87f37403565b499578a875c0a5297525ef96439647802a380ac2ea9025ce38a8acd34bf50e9863f88e9c1c46c0f3b2777d41bfc199a5681126a33216d4396a0d1ef8d640b5f543d8bdcba695c6aa9c3861787c24c947c2f5ccf94d01899994754edcf638da5bc4932d2851dd7c4364d18c994b00e817110b6d9f1f9c67904582776a9df674d0029e2604624a54ea428a33dfb5eb7ea69ad6c2d71b518e4fba101384d883d9afda8f00210245b3ac75dce7e55429c38e6c10df31006147ec0c43d5b608f232d8c7ff55a06b42e56b8e8ce0df534c5c64160e172ef31624831965e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18099);
 script_version("1.25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2005-0193");
 script_bugtraq_id(12334);

 script_name(english:"Mac OS X Security Update 2005-004");
 script_summary(english:"Check for Security Update 2005-004");

 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is missing a security update.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing Security Update 2005-004.  This security
update contains security fixes for the following application :

- iSync (local privilege escalation)");
 script_set_attribute(attribute:"solution", value:"http://docs.info.apple.com/article.html?artnum=301326");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0193");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/22");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.2");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.3");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2024 Tenable Network Security, Inc.");
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

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
# MacOS X 10.2.8, 10.3.9 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[789]\.)", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"SymbianConduit.bundle", path:"/System/Library/SyncServices", label:"SourceVersion");
 buf = exec(cmd:cmd);
 if ( int(buf) > 0 && int(buf) < 840200 ) security_hole(0);
}

