#TRUSTED 8653ec77661aba48fcd2fafd133b1c8f6b6c46d45e1e516c7c6df580d98c4e0f130d8005022366c4cd7d6edba606e94a497ed697211038fdd4ccc2ed7dbbe07a4efee6f09d14c5ba6754f641783754c4f07319968e25e4a5367a82f6d4b8cfd5371072f3148b08f3f48e92bbe79e5f1fbdf04d35ecd7a96089c2d2a130f4b0abe13a4474cc36af165fb92da731e56013f741abdd3e833849a35c00fc46b7641ca79d75323e8595c500d683d6df8d97dc87af34d2726fda727e580a3b368abc934300a9d4239ce9eb6aabfc44734891ff1c488b89c6a22db6ec5eda8f6f1bd28801901aba9905beb2a1cd0d36df1cc33db1215133f9966487f6e5da68a728da6655c304fabf9e5ce8942bf99c6b74f0623c49e6e01c43a05555751692444b677ebbc4d20e19077acabca4f660ec845e874cb8b64c839b1ce964107a1fb53c74b90b0ae1e62abe9c8dc708d5f675680e36d8ed50c65bf2442e5f6a3613f218b51ccb96ad0383e8f24147033afd815921e768bdaefa0b2101714ed17232fc19b69b5cc1fd74f114f074b18212f5535bd9ba4a1c4bd6c9a92c14fbad72dd1f78e22f3394f5a258ac5ecf1ee1526a9c3cc5ed2ea827054b5d57d3a5a8780b8282bdebc0f39ad73865acbd3946d387b4da0cbc38297b4beb48135aebef4c9def9582ca043ffc070b730328c059a6d3b40a09128b6a0353c01e38b3ce922a7ca4a2d3eb
#TRUST-RSA-SHA256 37883994037b8992987ad9c701298b68a3aefaebb4dde8f8ecd471059998bf740528148787cce6c3834d4abbd772c06ba1b89fe32362b761612222a6cea2dc887a0ffa0559edc985ed50a4d999275fd3a434f11299317fccdda3533e51fcf9ba67b5a73c3f80667164cb2c33d3613937c94056da9de0a6372865b9d24467052d9257caab9795aab0515818b491c754fb505cca71e30dadfe6e28c79b8bd3f3817962bc6744ece5e558010e173bb485d1d68883d9070adc7faca3b33007a84e82c10cf379ca9baaa3599c78e59bc66426e96675585d6a57811518866353b774057d0005884e1ff181307a4300064a21bd984bb82e20b678fa02831ab5d5b9b432822b089cb1ee0fe74d49a4f366a110e97b634517aeef5b8aef8bed7147d982c208f53d3b8d91fbece9f6f2cf9b237e702bec1dc36f161a01d0ae42f06d3834ff655c5f093f70860643909e21cf4624be80af59df9af8fe568b7981a2316755942516ca460385140710f56fdf03aa428b64151eacee846dfb16b7555b1491dfd28583c2331f697b3afeec9b9d6f73fe76c01c033b0f1459e8d6683baf4a7438f462ebd68063efab8e9d66bcb2999139ebb19629c7b3ee155bda9ca1548554191738e049598497a34d0713a5448f6ed31d1da260f9ba0a7ef29f61243f50156d20efc63c13c58e4aea000050770ef2500d5fc5a01c0a5a03de8f1fe7cf75af8ec4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34322);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

 script_cve_id("CVE-2008-4095");
 script_bugtraq_id(31505);

 script_name(english:"Mac OS X : Flip4Mac < 2.2.1 Unspecified Vulnerability");
 script_summary(english:"Check for Flip4Mac on the remote host");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a vulnerability in its WMV decoder.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Flip4Mac that contains
an unspecified vulnerability in its decoder. 

Flip4Mac is an extension that lets users read '.wmv' movie files.  By
enticing a user on the remote host to read a malformed '.wmv' file, an
attacker may be able to execute arbitrary commands on the remote
system.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1935549");
 script_set_attribute(attribute:"solution", value:"Upgrade to Flip4Mac Version 2.2.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-4095");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/01");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2024 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

if ( ! defined_func("bn_random") ) exit(0);

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

function _GetBundleVersionCmdInfo(file, path, label )
{
  local_var ret, suffix;
  local_var cmd;

   suffix = "/Contents/Info.plist";
   cmd    = "cat";


 file = str_replace(find:' ', replace:'\\ ', string:file);

 if ( !isnull(path) )
   {
   path = str_replace(find:' ', replace:'\\ ', string:path);
   ret = "cd " + path + " 2>/dev/null && ";
   }
 else
   ret = "";


 ret += cmd + " " + file + suffix + "|grep -A 1 " + label + " " + '| tail -n 1 | sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
;
 return ret;
}


function exec(cmd)
{
 local_var ret, buf;

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
if ( egrep(pattern:"Darwin.* ", string:uname) )
{
 cmd = _GetBundleVersionCmdInfo(file:"Flip4Mac WMV Import.component", path:"/Library/QuickTime", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 2.2.1.11
 if ( int(array[0]) < 2 ||
     (int(array[0]) == 2 && int(array[1]) < 2 ) ||
     (int(array[0]) == 2 && int(array[1]) == 2 && int(array[2]) < 1 ) ||
     (int(array[0]) == 2 && int(array[1]) == 2 && int(array[2]) == 1 && int(array[3]) < 11 ) )
 {
   security_hole(0);
 }
}
