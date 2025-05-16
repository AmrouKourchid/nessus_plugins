#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216269);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id("CVE-2024-6097");
  script_xref(name:"IAVB", value:"2025-B-0025");

  script_name(english:"Progress Telerik Reporting < 2025 Q1 (19.0.25.211) Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Progress Telerik Reporting installed on the remote Windows host is prior or equal to 2025 QA
(19.0.25.211). It is, therefore, affected by an information disclosure vulnerability. Information disclosure is
possible by a local threat actor through an absolute path vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.telerik.com/reporting/knowledge-base/kb-security-absolute-path-traversal-cve-2024-6097
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?708ba483");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress Telerik Reporting 2025 Q1 (19.0.25.211) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:telerik_reporting");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("progress_telerik_reporting_win_installed.nbin");
  script_require_keys("installed_sw/Progress Telerik Reporting", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Progress Telerik Reporting', win_local:TRUE);

var constraints = [
  {'max_version':'18.3.24.1218', 'fixed_version':'19.0.25.211'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
