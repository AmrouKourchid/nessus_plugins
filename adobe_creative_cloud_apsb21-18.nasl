##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147421);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-21068",
    "CVE-2021-21069",
    "CVE-2021-21078",
    "CVE-2021-28547"
  );
  script_xref(name:"IAVA", value:"2021-A-0124-S");

  script_name(english:"Adobe Creative Cloud < 5.4 Multiple Vulnerabilities (APSB21-18)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Creative Cloud instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud installed on the remote Windows host is prior to 5.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB21-18 advisory.

  - Adobe Creative Cloud Desktop Application version 5.3 (and earlier) is affected by a local privilege
    escalation vulnerability that could allow an attacker to call functions against the installer to perform
    high privileged actions. Exploitation of this issue does not require user interaction. (CVE-2021-21069)

  - Adobe Creative Cloud Desktop Application version 5.3 (and earlier) is affected by an Unquoted Service Path
    vulnerability in CCXProcess that could allow an attacker to achieve arbitrary code execution in the
    process of the current user. Exploitation of this issue requires user interaction (CVE-2021-21078)

  - Adobe Creative Cloud Desktop Application version 5.3 (and earlier) is affected by a file handling
    vulnerability that could allow an attacker to cause arbitrary file overwriting. Exploitation of this issue
    requires physical access and user interaction. (CVE-2021-21068)

  - Adobe Creative Cloud Desktop Application for macOS version 5.3 (and earlier) is affected by a privilege
    escalation vulnerability that could allow a normal user to delete the OOBE directory and get permissions
    of any directory under the administrator authority. (CVE-2021-28547)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb21-18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e798cb5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud version 5.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21069");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Creative Cloud");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Creative Cloud', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '5.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
