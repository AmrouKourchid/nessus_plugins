#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109143);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/30");

  script_cve_id("CVE-2018-8840");
  script_xref(name:"TRA", value:"TRA-2018-07");
  script_xref(name:"ICSA", value:"18-107-01");

  script_name(english:"Schneider Electric InTouch Machine Edition RCE (Apr 2018)");

  script_set_attribute(attribute:"synopsis", value:
"Schneider Electric InTouch Machine Edition requires a security update.");
  script_set_attribute(attribute:"description", value:
"An installed version of Schneider Electric InTouch Machine Edition is 
vulnerable to RCE and therefore requires a security update.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-07");
  # https://sw.aveva.com/hubfs/pdf/security-bulletin/LFSec00000125-2.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcfab1a4");
  script_set_attribute(attribute:"see_also", value:"https://ics-cert.us-cert.gov/advisories/ICSA-18-107-01");
  script_set_attribute(attribute:"solution", value:
"Update to Schneider Electric InTouch Machine Edition 8.1 SP1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:schneider-electric:wonderware_intouch");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:schneider_electric:wonderware_intouch_machine_edition");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("scada_app_schneider_electric_itme_detection_local.nbin");
  script_require_keys("installed_sw/Schneider Electric InTouch Machine Edition");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("global_settings.inc");
include("smb_func.inc");

appname = 'Schneider Electric InTouch Machine Edition';
get_install_count(app_name:appname, exit_if_zero:true);
port = kb_smb_transport();
installs = get_installs(app_name:appname, exit_if_not_found:true);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];

  fix = '2601.1803.2601.0';

  vcomp_out = ver_compare(ver:version, fix:fix);
  if (!isnull(vcomp_out) && vcomp_out < 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
  }
}

if (report != '')
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
else
  audit(AUDIT_INST_VER_NOT_VULN, appname);
