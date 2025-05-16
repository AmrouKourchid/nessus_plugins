#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190614);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2023-28407", "CVE-2023-32647", "CVE-2023-38561");
  script_xref(name:"IAVB", value:"2024-B-0014");

  script_name(english:"Intel Extreme Tuning Utility < 7.12.0.29 Multiple Vulnerabilities (intel-sa-00955)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Intel Extreme Tuning Utility installed on the remote host is prior to 7.12.0.29. It is, therefore, affected by
multiple vulnerabilities as referenced in the intel-sa-00955 advisory.

  - Uncontrolled search path in some Intel(R) XTU software before version 7.12.0.29 may allow an authenticated
    user to potentially enable escalation of privilege via local access. (CVE-2023-28407)

  - Improper access control in some Intel(R) XTU software before version 7.12.0.29 may allow an authenticated
    user to potentially enable escalation of privilege via local access. (CVE-2023-32647, CVE-2023-38561)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade Extreme Tuning Utility based upon the guidance specified in intel-sa-00955.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38561");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:extreme_tuning_utility");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_xtu_win_installed.nbin");
  script_require_keys("installed_sw/Intel Extreme Tuning Utility", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Intel Extreme Tuning Utility', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '7.12.0.29' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
