#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151904);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/07");

  script_cve_id("CVE-2021-2344", "CVE-2021-2371", "CVE-2021-2428");
  script_xref(name:"IAVA", value:"2021-A-0326");

  script_name(english:"Oracle Coherence Multiple Vulnerabilities (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0 versions of Coherence installed on the remote host are
affected by multiple vulnerabilities as referenced in the July 2021 CPU advisory.

  - Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Core). Supported
    versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle
    Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence.
    (CVE-2021-2428)

  - Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Core). Supported
    versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise
    Oracle Coherence. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    hang or frequently repeatable crash (complete DOS) of Oracle Coherence. (CVE-2021-2344, CVE-2021-2371)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2428");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:coherence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_coherence_installed.nbin");
  script_require_keys("installed_sw/Oracle Coherence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Coherence');

var constraints = [
  { 'min_version' : '3.7.1.0', 'fixed_version' : '3.7.1.22' },
  { 'min_version' : '12.1.3.0.0', 'fixed_version' : '12.1.3.0.12' },
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.15' },
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.10' },
  { 'min_version' : '14.1.1.0.0', 'fixed_version' : '14.1.1.0.6' }
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
