#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186687);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/18");

  script_cve_id("CVE-2023-28523", "CVE-2023-28526", "CVE-2023-28527");
  script_xref(name:"IAVA", value:"2023-A-0668");

  script_name(english:"IBM Informix Dynamic Server 12.10.x, 14.10.x Buffer Overflow (7070188)");

  script_set_attribute(attribute:"synopsis", value:
"A database server installed on the remote host is affected by a buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Informix Dynamic Server installed on the remote is either 12.10.x or 14.10.x prior to 14.10.FC10W1. 
It is, therefore, affected by a buffer overflow, caused by improper bounds checking. A local privileged user could overflow a buffer and
execute arbitrary code on the system or cause a denial of service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7070188");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Informix Dynamic Server to the fixed version mentioned in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28523");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix_dynamic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_informix_server_installed.nasl");
  script_require_keys("installed_sw/IBM Informix Dynamic Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('smb_func.inc');

var app_name = 'IBM Informix Dynamic Server';
var install = vcf::get_app_info(app:app_name, win_local:TRUE);

var ver   = install['version'];
var path  = install['path'];
var fix = NULL;

if (ver !~ "^14\.10\." && ver !~ "^12\.10\.")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

# https://www.ibm.com/support/pages/ibm-informix-version-number
var item = pregmatch(pattern:"[cC]([0-9]+)[wW]?([0-9]|$)", string:ver);
if (!empty_or_null(item) && !empty_or_null(item[1]) && (item[1] <= 10 && (empty_or_null(item[2]) || item[2] < 1))) 
    fix = '14.10.xC10W1';
    
if (empty_or_null(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

var port = kb_smb_transport();

var report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix + '\n';

var server_instances = get_kb_item('Host/' + app_name + '/Server Instances');

if (!empty_or_null(server_instances))
{
  var instance_list = split(server_instances, sep:' / ', keep:FALSE);
  report += '  Server instances  : ' + '\n      - ' + join(instance_list, sep:'\n      - ') + '\n';
}

security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
