#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183300);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id("CVE-2023-32970", "CVE-2023-32973");

  script_name(english:"QNAP QTS / QuTS hero Multiple Vulnerabilities (QSA-23-41)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS / QuTS hero installed on the remote host is affected by multiple vulnerabilities as referenced
in the QSA-23-41 advisory.

  - A NULL pointer dereference vulnerability has been reported to affect several QNAP operating system 
    versions. If exploited, the vulnerability could allow authenticated administrators to launch a 
    denial-of-service (DoS) attack via a network. QES is not affected. (CVE-2023-32970)

  - A buffer copy without checking size of input vulnerability has been reported to affect several QNAP 
    operating system versions. If exploited, the vulnerability could allow authenticated administrators to 
    execute code via a network. (CVE-2023-32973)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/QSA-23-41");
  script_set_attribute(attribute:"solution", value:
"Apply the solution referenced in the QSA-23-41 advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32973");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin", "qnap_quts_hero_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  { 'min_version' : '4.5.0', 'max_version' : '4.5.4', 'product' : 'QTS', 'fixed_display' : 'QTS 4.5.4.2467 build 20230718', 'Number' : '2467', 'Build' : '20230718' },
  { 'min_version' : '5.0.0', 'max_version' : '5.0.1', 'product' : 'QTS', 'fixed_display' : 'QTS 5.0.1.2425 build 20230609', 'Number' : '2425', 'Build' : '20230609' },
  { 'min_version' : '5.1.0', 'max_version' : '5.1.0', 'product' : 'QTS', 'fixed_display' : 'QTS 5.1.0.2444 build 20230629', 'Number' : '2444', 'Build' : '20230629' },
  { 'min_version' : '4.5.0', 'max_version' : '4.5.4', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h4.5.4.2476 build 20230728', 'Number' : '2476', 'Build' : '20230728' },
  { 'min_version' : '5.0.0', 'max_version' : '5.0.1', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h5.0.1.2515 build 20230907', 'Number' : '2515', 'Build' : '20230907' },
  { 'min_version' : '5.1.0', 'max_version' : '5.1.0', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h5.1.0.2424 build 20230609', 'Number' : '2424', 'Build' : '20230609' }
];
vcf::qnap::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
