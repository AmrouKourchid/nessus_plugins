#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190602);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/24");

  script_cve_id("CVE-2023-36490", "CVE-2023-41090");
  script_xref(name:"IAVB", value:"2024-B-0014");

  script_name(english:"Intel Memory and Storage Tool < 2.3 Multiple Vulnerabilities (INTEL-SA-00967)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Intel Memory and Storage Tool installed on the remote host is prior to 2.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the INTEL-SA-00967 advisory.

  - Improper initialization in some Intel(R) MAS software before version 2.3 may allow an authenticated user
    to potentially enable denial of service via local access. (CVE-2023-36490)

  - Race condition in some Intel(R) MAS software before version 2.3 may allow a privileged user to potentially
    enable escalation of privilege via local access. (CVE-2023-41090)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00967.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a86bc20e");
  script_set_attribute(attribute:"solution", value:
"Upgrade Intel Memory and Storage Tool based upon the guidance specified in INTEL-SA-00967.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41090");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:intel:memory_and_storage_tool");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_mas_win_installed.nbin");
  script_require_keys("installed_sw/Intel Memory and Storage Tool", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Intel Memory and Storage Tool', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
