#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194907);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2022-21381", "CVE-2022-21382", "CVE-2022-21383");

  script_name(english:"Oracle Session Border Controller (January 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions 8.4 and 9.0 of Oracle Enterprise Session Border Controller product of Oracle Communications installed
on the remote host is affected by multiple vulnerabilities as referenced in the January 2022 CPU advisory, including 
the following:

  - Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise 
    Oracle Enterprise Session Border Controller (component: WebUI). While the vulnerability is in Oracle Enterprise 
    Session Border Controller, attacks may significantly impact additional products. Successful attacks of 
    this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Enterprise 
    Session Border Controller accessible data as well as unauthorized read access to a subset of data (CVE-2022-21381) 
    or unauthorized creation, deletion or modification access to critical data or all Oracle Enterprise Session Border 
    Controller accessible data (CVE-2022-21382).

  - Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle 
    Enterprise Session Border Controller (component: Log). Successful attacks of this vulnerability can result in 
    unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Enterprise Session Border 
    Controller. (CVE-2022-21383)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21381");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21382");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:communications_session_border_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_sbc_detect.nbin");
  script_require_keys("Host/Oracle/SBC");

  exit(0);
}

var app   = 'Oracle SBC';
var fixed_8_4_patch = 9;
var fixed_9_0_patch = 3;

# Get the current version
var version = get_kb_item_or_exit('Host/Oracle/SBC/version');
var patch = get_kb_item('Host/Oracle/SBC/patch');
if (empty_or_null(patch))
  patch = 0;
else
  patch = int(patch);

var report;
if (version =~ "^8\.4" && patch < fixed_8_4_patch)
{
  report = '\n  Installed version : ' + version +
           '\n  Installed patch   : ' + patch +
           '\n  Fixed patch       : ' + fixed_8_4_patch + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else if (version =~ "^9\.0" && patch < fixed_9_0_patch)
{
  report = '\n  Installed version : ' + version +
           '\n  Installed patch   : ' + patch +
           '\n  Fixed patch       : ' + fixed_9_0_patch + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
