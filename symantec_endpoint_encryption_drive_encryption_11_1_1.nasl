#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91124);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/13");

  script_cve_id("CVE-2015-8156");
  script_bugtraq_id(90050);

  script_name(english:"Symantec Endpoint Encryption < 8.x / 9.x < 11.1.1 Unquoted Search Path Local Privilege Escalation (SYM16-006)");
  script_summary(english:"Checks the version of Symantec Endpoint Encryption Drive Encryption.");

  script_set_attribute(attribute:"synopsis", value:
"A drive encryption management agent installed on the remote Windows
host is affected by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Symantec Endpoint Encryption (SEE) Drive Encryption
Client installed on the remote Windows host is prior to 11.1.1.
It is, therefore, affected by a privilege escalation vulnerability due
to an unquoted search path in EEDService. A local attacker can exploit
this to escalate privileges.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/0/0/SYMSA1362
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8e22aa6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Encryption version 11.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8156");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_encryption");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_endpoint_encryption_drive_encryption_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Symantec Endpoint Encryption Drive Encryption Client");

  exit(0);
}

include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app_name = "Symantec Endpoint Encryption Drive Encryption Client";
var fix      = "11.1.1.0";
var install = get_single_install(app_name:app_name);

var version = install['version'];
var path    = install['path'];

# Bulletin states 8.x is unaffected
if(version =~ "^8\.")
  audit(AUDIT_PACKAGE_NOT_AFFECTED, app_name);

# any other version < 11.1.1
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  var port = get_kb_item("SMB/transport");
  if (empty_or_null(port))
    port = 445;

  var report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
