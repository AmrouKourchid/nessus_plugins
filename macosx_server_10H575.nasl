#TRUSTED 025e3e5a4b0a1c26fb7750b5f91a495ab30efb5ece572711ca3cd332849b240663bf960d7437be86350dd53d449b0cd753dcbc91bf13b5f13c5eb05aba010e17d091fe6052e85c0f080ba8a1ff3dabbd69bc630c4dc60a04cf409825f30e3a143c505eb1d580ef18504b9b1b07072b093b7cedda6ffdd93f5e28f54dd53cdd70af7a084585540f73551d005efb7f79c7dbe4e19ab41baa47ccf3f26ebeb54d5509afc104346abe182be455173a644b99595fd79d36ea5e1869d1e7dc2c54f66a45651a2be79c0b43d42690db4395e50ed57722096f479cf8995f32f902b413eb7ccdb7b3473b7920c2cdeb185bca272f95fb46e9c58f34ac157b52587e76f52286956386b35a6101aafdd2cfc212abe4d9696b007899c1c94afff1cf874d25b28cdceed26194248ce9428858aad4a45095813cc60c0a774eedd2ec468f832564fbf4fd8fd0cb688f8fa6cd6b012d5597c5150d324e960af56c6d67c808179b86f827f995b0dd652118a63cbb07f3db38e96aced54497c5ec4bcb3944e29febaecbe2152eddd1bc3e99776ae5446e0551a038c2b284e4b358632719d52aece0560fc195abd1d6ea4b00ba669fc678860b348b364053aabb74e4cce4d40d65de87c0a1b0c1f49e9ffc4fcd6686faef7580506c31df9149b56cd64cd399b1466a2a63729a29eaff3212dddf3897d82efc27741c93b6bea2700b63c835499b3eec11
#TRUST-RSA-SHA256 b08dcecbc4f58d8686a802c0031bad4f599be2d3b8202dbe63ba3c8fa5af015ce5dd65dbebd741b1ca5dedd05089702cabd46bc884d085fd0a975130c1b3a52b4b3d7f5292483caeb9181d1b90afe2293f05ccb5243bed3ccc0182523a843281c5359e8d9a4b9864db71dd41df14d36f5d8a9d43315f19ce21e9cfbc8c9e552693c1ba2940aa2a31d65d7b0930e7d9647480f8843586fc7959a3dbe350902426cb6634ea9f179962c21aebd66f330d42a25898d84dec5c47947550c55a9f3e2ecb0ab4d0d3ea5c48311b4a0cbd4c30460efbea218648dc9061b16125c2ba35feacdcf678b4c41352c9d686a8118006844ea13adb5959016722983499324efef7b100e9a7c8818e5a6157d7827c2a463ec8c00bef62f7190ad002651e4e74a338eece6f772033ad02b8351ed6cfa57899d8bc56ad9d022f970ccc260e463408fd68380d450e35ede2d595cc7efda130e4cf9b507516a517748b905b025464f32b0b68dfade64314ae3d3d6ad849b6246f27d0777051679d0e7c55420a3330b6c331f59da85b5d04eeb73e21560c9c13f30f43436edf832e5a942b7856b4b55f5adb53d392f13d2fbc8c9781b0072c8341d4d712d28b1a19b4fd07f393929eb40f847d2ce8a26f8f88787bf98ec3058228ce03e9b3b190447c9b3b4e2706f0af41013ccd90d0fc5eb3525d7f25b9feab88deb7d3ce04d09a9898e3622c1768c8a6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50681);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2010-4011");
  script_bugtraq_id(44874);

  script_name(english:"Mac OS X Server v10.6.5 (10H575)");
  script_summary(english:"Checks ProductBuildVersion in /System/Library/CoreServices/ServerVersion.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that may be affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A memory aliasing issue in Dovecot's handling of user names in Mac OS
X Server v10.6.5 may result in a user receiving mail intended for
other users. 

Note that this vulnerability arises only on Mac OS X Server systems
when Dovecot is configured as a mail server."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4452"
  );
  # http://lists.apple.com/archives/security-announce/2010/Nov/msg00001.html
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?8f03ccf8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X Server v10.6.5 (10H575) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4011");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/uname", "MacOSX/Server/Version");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(1, "info_connect() failed.");
    buf = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }

  return buf;
}


uname = get_kb_item("Host/uname");
if (!uname) exit(0, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6.");


version = get_kb_item("MacOSX/Server/Version");
if (!version) exit(1, "Failed to retrieve the Mac OS X Server version.");
if ("Server 10.6" >!< version) exit(0, "The host is running "+version+" and thus not affected.");


# And check it.
#
# nb: Apple says only 10H574 is affected.
if ("(10H574)" >< version)
{
  # Unless we're paranoid, make sure Dovecot is being used for mail.
  gs_opt = get_kb_item("global_settings/report_paranoia");
  if (gs_opt && gs_opt != 'Paranoid')
  {
    status = get_kb_item("MacOSX/Server/mail/Status");
    if (!status) exit(1, "Failed to retrieve the status of the 'mail' service.");

    if ("RUNNING" >!< status)
      exit(0, "The mail service is not running, and thus the host is not affected.");

    cmd = 'serveradmin settings mail:postfix:mailbox_transport';
    buf = exec(cmd:cmd);
    if (!buf) exit(1, "Failed to run '"+cmd+"'.");

    if (!eregmatch(pattern:'mailbox_transport *= *"dovecot"', string:buf)) 
      exit(0, "The mail service does not use Dovecot, and thus the host is not affected.");

    report_trailer = '';
  }
  else report_trailer = 
    '\n' +
    'Note, though, that Nessus did not check whether the mail service is\n' +
    'running or Dovecot is in use because of the Report Paranoia setting in\n' +
    'effect when this scan was run.\n';

  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    version = strstr(version, "Server ") - "Server ";

    report = 
      '\n  Installed system version : ' + version + 
      '\n  Fixed system version     : 10.6.5 (10H575)\n';
    if (report_trailer) report += report_trailer;

    security_warning(port:0, extra:report);
  }
  else security_warning(0);

  exit(0);
}
else exit(0, "The remote host is not affected since Mac OS X Server build version "+version+" is installed.");
