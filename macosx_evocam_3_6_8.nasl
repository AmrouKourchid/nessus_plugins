#TRUSTED a77b0a0169d046bc7ee746065a28a4281b12a8fb217bdc08b136db02313aebe059a1aa7877a63d0d99727b44792f45ca687e878c181213d3de1ac34afd4c9d7c7bb792171123d636f4e49c8c7a2057fa606a85d27f1724e45bdea41c18fbf3f117bb0a5a1ca56c3e2b9b84ebf3a4eb82a21b7ce879d0c4254c44b5f73318a9a3adb90547945f34550d89d9c88ef2390f061943dc44ab3809df0af4d56d5092cc48eba24af70dbb96916953ca528e2cde216d6b8b59e3f0019ecd63a52de7d26a1851d612fa4dda90560174ab39e10bec88a47630115c3c4be64be60b060494056bbff3c9c39fa70dea9de87adefb9eabb6845291cf28afa80f4ec1cf68a0a07fa0b039a57fc1faaf73b89f20d69444a96fbf25cbba53b4a66d0c86b52e8326cc5877a5b15dc27709be78e88d1add57a17fd0582e4f580335dfdbc9d664e806628f5746bd8dbe90790c3cf8b1cd860f5f4314356f5f5d7449237a4dc053b96236dbb5d35dc558454426bf0d1aa53e7eed011e7d67a16ab62a34047c6c2e92f53d38eca6ae3386fd378882f3380d09448d77e9baa37bfdf1d42594519c72700c465cdd29f59fac790e2e4a00bf5f3cc545b1c8b8d651f3bb9e07798fc5952fe9c9d9fefcd2a984fe9aab143b65a0a2f7e059e108f5ebc7906d02d140feae858e7fbfce43d54ebd7181fb7a781485ff36d0841db0c5d678536958f1a57faf0a3557
#TRUST-RSA-SHA256 6a6279fd47dbe162e25f1725d8461d38162d4aa4a1ffa4d6687a7b677cf39db07138568c75155709882a5c3d191de629bda260f2a65a0d8e566f136b3af67ca6065bccaf1ee0269e2d926a55b73b2d8409a7b754c0e80f849333dd89cbb8f150f4f6e89a71fcb702406c1ad4c7e11891fc207dc6da4481ac855364831729d4fb357a0fa55da5d91dfc1de163a1f73d8013a35ad11612150ff2753d799c04367b87fe9c1a2baaba74d0c2ba2930ebdd3313e1c34f63e3a196931891136337ac5a4fd70b99c2f4c0459f79dbecc8e732d7a38fedd1f06ca6fd7d4d37a7171b2cf4e0279cfa76071a0b39afd8b3620db30b098300b96c11ef3b7fb51c51afd936a29c9a0155f570bc081c66fa5689789e78efd4de393b7240e1957153230dc6c82e997455023aaa0ef74be3f096edd2dfe3d3791977572a87694ad8b8155a4bef89dd9e66b9cc2da1436a7483239f8df4ef3b0b01dcdb2d373bd0c99efe997f821e2190382dc94f65dc29a0f0bea55fb8a0add68440bbc1dbb059743c4c97d5d599e4d9c1fb110c5bf34058f6adb0785593db69579b33f5315605a4cfb2b479c93de1d04bfa19e2e02d1508d60f8f99347c5ae5a7a3d8de2074b878e2b00b806834fe0f1ecd7a264c283fde57a14c73db9bbe8c90e6598120aea1b1d056993f1535bb003635419b6a4525762dee6c93c8497069d2d38a56662a9ae88a46612333c2
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");


if (description)
{
  script_id(47682);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2010-2309");
  script_bugtraq_id(40489);
  script_xref(name:"EDB-ID", value:"13735");

  script_name(english:"EvoCam 3.6.6 / 3.6.7 Web Server GET Request Overflow");
  script_summary(english:"Checks version of EvoCam");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that may be susceptible to a remote
buffer overflow attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of EvoCam installed on the Mac OS X host is either 3.6.6
or 3.6.7.  Such versions reportedly contain a buffer overflow in the
Web Server component. 

Using an overly long GET request, an unauthenticated remote attacker
may be able to leverage this vulnerability to execute arbitrary code
on the remote host subject to the privileges under which the
application runs."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to EvoCam 3.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2309");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MacOS X EvoCam HTTP GET Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "http_version.nasl");
  script_require_keys("Host/MacOSX/packages", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Unless we're paranoid, make sure the service is enabled.
if (get_kb_item("global_settings/report_paranoia") != 'Paranoid')
{
  found = FALSE;
  ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);

  foreach var port (ports)
  {
     soc = open_sock_tcp(port);
     if (soc)
     {
      send(socket:soc, data:http_get(item:"/", port:80));
      res = recv(socket:soc, length:1024);

      if (
        strlen(res) &&
        (
          "<title>EvoCam</title>" >< res ||
          '<applet archive="evocam.jar" code="com.evological.evocam.class"' >< res
        )
      ) found = TRUE;
      close(soc);
    }
    if (found) break;            
  } 
  if(!found) exit(0, "The EvoCam web server is not listening on the remote host.");
}


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
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


plist = "/Applications/EvoCam.app/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 3 && 
  ver[1] == 6 && 
  (ver[2] == 6 || ver[2] == 7)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.6.8\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since EvoCam "+version+" is installed.");
