#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179310);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id("CVE-2023-32481", "CVE-2023-32482", "CVE-2023-32483");
  script_xref(name:"IAVB", value:"2023-B-0056-S");

  script_name(english:"Dell Wyse Management Suite < 4.1 Multiple Vulnerabilities (DSA-2023-240)");

  script_set_attribute(attribute:"synopsis", value:
"Dell Wyse Management Suite installed on the local host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Wyse Management Suite installed on the remote host is prior to 4.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the DSA-2023-240 advisory.

  - Wyse Management Suite versions prior to 4.1 contain a denial-of-service vulnerability. An authenticated
    malicious user can flood the configured SMTP server with numerous requests in order to deny access to the
    system. (CVE-2023-32481)

  - Wyse Management Suite versions prior to 4.1 contain an improper authorization vulnerability. An
    authenticated malicious user with privileged access can push policies to unauthorized tenant group.
    (CVE-2023-32482)

  - Wyse Management Suite versions prior to 4.1 contain a sensitive information disclosure vulnerability. An
    authenticated malicious user having local access to the system running the application could exploit this
    vulnerability to read sensitive information written to log files. (CVE-2023-32483)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-uk/000215351/dsa-2023-240-dell-wyse-management-suite
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f231549e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Wyse Management Suite version 4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32482");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:wyse_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_wyse_management_suite_win_installed.nbin");
  script_require_keys("installed_sw/Dell Wyse Management Suite");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Dell Wyse Management Suite', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '4.1' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
