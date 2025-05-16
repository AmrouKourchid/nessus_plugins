#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132992);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2019-13117",
    "CVE-2019-13118",
    "CVE-2019-16168",
    "CVE-2020-2583",
    "CVE-2020-2585",
    "CVE-2020-2590",
    "CVE-2020-2593",
    "CVE-2020-2601",
    "CVE-2020-2604",
    "CVE-2020-2654",
    "CVE-2020-2655",
    "CVE-2020-2659"
  );
  script_bugtraq_id(109323);
  script_xref(name:"IAVA", value:"2020-A-0023-S");

  script_name(english:"Oracle Java SE 1.7.0_251 / 1.8.0_241 / 1.11.0_6 / 1.13.0_2 Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 7 Update 251, 8 Update 241,
11 Update 6, or 13 Update 2. It is, therefore, affected by multiple
vulnerabilities:

  - Oracle Java SE and Java SE Embedded are prone to a severe division by zero, over 'Multiple' protocol.
    This issue affects the 'SQLite' component.(CVE-2019-16168)

  - Oracle Java SE and Java SE Embedded are prone to format string vulnerability, leading to a read
    uninitialized stack data over 'Multiple' protocol. This issue affects the 'libxst' component.
    (CVE-2019-13117, CVE-2019-13118)

  - Oracle Java SE and Java SE Embedded are prone to a remote security vulnerability. An unauthenticated
    remote attacker can exploit this over 'Kerberos' protocol. This issue affects the 'Security' component.
    (CVE-2020-2601, CVE-2020-2590)

  - Oracle Java SE/Java SE Embedded are prone to a remote security vulnerability. An unauthenticated
    remote attacker can exploit this overmultiple protocols. This issue affects the 'Serialization' component.
    (CVE-2020-2604, CVE-2020-2583)

  - Oracle Java SE/Java SE Embedded are prone to a remote security vulnerability. Tn unauthenticated
    remote attacker can exploit this over multiple protocols. This issue affects the 'Networking' component.
    (CVE-2020-2593, CVE-2020-2659)

  - Oracle Java SE are prone to a remote security vulnerability. An unauthenticated remote attacker can exploit
    this over multiple protocols. This issue affects the 'Libraries' component. (CVE-2020-2654)

  - Oracle Java SE are prone to a multiple security vulnerability. An unauthenticated remote attacker can exploit
    this over multiple protocols. This issue affects the 'JavaFX' component. (CVE-2020-2585)

  - Oracle Java SE are prone to a multiple security vulnerability. An unauthenticate remote attacker can exploit
    this over 'HTTPS' protocols. This issue affects the 'JSSE' component. (CVE-2020-2655)

Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/security-alerts/cpujan2020.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d22a1e87");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 13 Update 2 , 11 Update 6, 8 Update 241
/ 7 Update 251 or later. If necessary, remove any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_ports("SMB/Registry/Enumerated");
  script_require_keys("installed_sw/Java");
   
  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var os = get_kb_item('Host/OS');
if ('Windows' >!< os && empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  audit(AUDIT_OS_NOT, 'affected');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);
# 7u251, 8u241, 11u6, 13u2
var constraints = [
  { 'min_version' : '7.0.0',  'fixed_version' : '7.0.251', 'fixed_display' : 'Upgrade to version 7.0.251 or greater' },
  { 'min_version' : '8.0.0',  'fixed_version' : '8.0.241', 'fixed_display' : 'Upgrade to version 8.0.241 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.6',  'fixed_display' : 'Upgrade to version 11.0.6 or greater' },
  { 'min_version' : '13.0.0', 'fixed_version' : '13.0.2',  'fixed_display' : 'Upgrade to version 13.0.2 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
