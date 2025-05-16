#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183970);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id("CVE-2023-20032", "CVE-2023-20052");

  script_name(english:"QNAP QTS / QuTS hero Multiple Vulnerabilities in ClamAV (QSA-23-26)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS / QuTS hero installed on the remote host is affected by multiple vulnerabilities as referenced
in the QSA-23-26 advisory.

  - A vulnerability in the HFS+ partition file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and 
    earlier, and 0.103.7and earlier could allow an unauthenticated, remote attacker to execute arbitrary 
    code. This vulnerability is due to a missing buffer size check that may result in a heap buffer overflow 
    write. An attacker could exploit this vulnerability by submitting a crafted HFS+ partition file to be 
    scanned by ClamAV on an affected device. A successful exploit could allow the attacker to execute 
    arbitrary code with the privileges of the ClamAV scanning process, or else crash the process, resulting 
    in a denial of service (DoS) condition. (CVE-2023-20032)

  - A vulnerability in the DMG file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and earlier, and 
    0.103.7 and earlier could allow an unauthenticated, remote attacker to access sensitive information on an 
    affected device. This vulnerability is due to enabling XML entity substitution that may result in XML 
    external entity injection. An attacker could exploit this vulnerability by submitting a crafted DMG file 
    to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to leak bytes 
    from any file that may be read by the ClamAV scanning process. (CVE-2023-20052)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/QSA-23-26");
  script_set_attribute(attribute:"solution", value:
"Apply the solution referenced in the QSA-23-26 advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/27");

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
  { 'min_version' : '5.0.0', 'max_version' : '5.0.1', 'product' : 'QTS', 'fixed_display' : 'QTS 5.0.1.2376 build 20230421', 'Number' : '2376', 'Build' : '20230421' },
  { 'min_version' : '5.0.0', 'max_version' : '5.0.1', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h5.0.1.2376 build 20230421', 'Number' : '2376', 'Build' : '20230421' }
];
vcf::qnap::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
