#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52671);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2011-0609");
  script_bugtraq_id(46860);
  script_xref(name:"CERT", value:"192052");
  script_xref(name:"EDB-ID", value:"17027");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Adobe Acrobat 9.x / 10.x Unspecified Memory Corruption (APSB11-06)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Acrobat 9.x <
9.4.3 or 10.x < 10.0.2. Such versions are affected by an unspecified
memory corruption vulnerability in authplay.dll.

A remote attacker could exploit this by tricking a user into viewing
maliciously crafted SWF content, resulting in arbitrary code
execution.

This bug is currently being exploited in the wild.");
  # http://bugix-security.blogspot.com/2011/03/cve-2011-0609-adobe-flash-player.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82775d9e");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa11-01.html");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/support/security/bulletins/apsb11-06.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat 9.4.3 / 10.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0609");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player AVM Bytecode Verification Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("installed_sw/Adobe Acrobat");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include('install_func.inc');

var install = get_single_install(app_name:'Adobe Acrobat', exit_if_unknown_ver:TRUE);

var version = install.version;
var version_ui = install.display_version;

var version_report;
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

var ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

var report = '';
if (
  (ver[0] == 9 && ver[1]  < 4) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 3)
)
{
  report =
    '\n  Path              : '+path+
    '\n  Installed version : '+version_report+
    '\n  Fixed version     : 9.4.3 / 10.0.2\n';
}
# For 10.x versions, we have to look at the version of authplay.dll
else if (ver[0] == 10 && ver[1] == 0 &&
        (ver[2] < 1 || (ver[2] == 1 && ver[3] <= 434)))
{
  var path = install.path;
  var name   = kb_smb_name();
  var port   = kb_smb_transport();
  var login  = kb_smb_login();
  var pass   = kb_smb_password();
  var domain = kb_smb_domain();

#  if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
#  soc = open_sock_tcp(port);
#  if (!soc) exit(1, "Failed to open a socket on port "+port+".");

#  session_init(socket:soc, hostname:name);

  if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


  var share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  var dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Acrobat\\authplay.dll', string:path);

  var rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to '+share+' share.');
  }

  var fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel();
    exit(1, 'Unable to access : '+path+'\\Acrobat\\authplay.dll.');
  }
  var dllver;
  dllver = GetProductVersion(handle:fh);
  dllver = split(dllver, sep:',', keep:FALSE);

  CloseFile(handle:fh);
  NetUseDel();
  if (isnull(dllver)) exit(1, 'Can\'t get the version of '+path+'\\Acrobat\\authplay.dll.');

  var dllversion = join(sep:'.', dllver);
  var fixdll = '10.2.153.1';
  if (ver_compare(ver:dllversion, fix:fixdll) == -1)
  {
    report =
      '\n  DLL       :       ' + path + '\\Acrobat\\authplay.dll' +
      '\n  Installed version : ' + dllversion +
      '\n  Fixed version     : ' + fixdll + '\n';
  }
}
if (report)
{
  if (report_verbosity > 0) security_hole(port:get_kb_item('SMB/transport'), extra:report);
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "The host is not affected.");

