#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126821);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/25");

  script_cve_id(
    "CVE-2019-2745",
    "CVE-2019-2762",
    "CVE-2019-2766",
    "CVE-2019-2769",
    "CVE-2019-2786",
    "CVE-2019-2816",
    "CVE-2019-2818",
    "CVE-2019-2821",
    "CVE-2019-2842",
    "CVE-2019-6129",
    "CVE-2019-7317"
  );
  script_bugtraq_id(
    108098,
    109184,
    109185,
    109186,
    109187,
    109188,
    109189,
    109201,
    109206,
    109210,
    109212
  );
  script_xref(name:"IAVA", value:"2019-A-0255");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Java SE 1.7.0_231 / 1.8.0_221 / 1.11.0_4 / 1.12.0_2 Multiple Vulnerabilities (Jul 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 7 Update 231, 8 Update 221,
11 Update 4, or 12 Update 2. It is, therefore, affected by multiple
vulnerabilities:

  - Unspecified vulnerabilities in the utilities and JCE 
    subcomponents of Oracle Java SE, which could allow an 
    unauthenticated remote attacker to cause a partial denial 
    of service. (CVE-2019-2762, CVE-2019-2769, CVE-2019-2842)

  - An unspecified vulnerability in the security subcomponent 
    of Oracle Java SE, which could allow an unauthenticated 
    local attacker to gain unauthorized access to critical Java 
    SE data. (CVE-2019-2745)

  - Unspecified vulnerabilities in the networking and security 
    subcomponents of Oracle Java SE, which could allow an 
    unauthenticated remote attacker to gain unauthorized 
    access to Java SE data. Exploitation of this vulnerability 
    requires user interaction. 
    (CVE-2019-2766, CVE-2019-2786, CVE-2019-2818)

  - An unspecified vulnerability in the networking subcomponent
    of Oracle Java SE, which could allow an unauthenticated 
    remote attacker unauthorized read, update, insert or
    delete access to Java SE data. (CVE-2019-2816)

  - An unspecified vulnerability in the JSSE subcomponent of 
    Oracle Java SE, which could allow an unauthenticated, 
    remote attacker to gain unauthorized access to critical
    Java SE data. Exploitation of this vulnerability requires 
    user interaction. (CVE-2019-2821)

  - A use after free vulnerability exists in the libpng 
    subcomponent of Oracle Java SE. An unauthenticated, 
    remote attacker can exploit this to cause a complete
    denial of service condition in Java SE. Exploitation 
    of this vulnerability requires user interaction.
    (CVE-2019-7317)

Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9aa2b901");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 12 Update 2 , 11 Update 4, 8 Update 221
/ 7 Update 231 or later. If necessary, remove any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2816");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2821");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("installed_sw/Java");
  script_require_ports("SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var os = get_kb_item('Host/OS');
if ('Windows' >!< os && empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  audit(AUDIT_OS_NOT, 'affected');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);
# 7u231, 8u221, 11u4, 12u2
var constraints = [
  { 'min_version' : '7.0.0',  'fixed_version' : '7.0.231', 'fixed_display' : 'Upgrade to version 7.0.231 or greater' },
  { 'min_version' : '8.0.0',  'fixed_version' : '8.0.221', 'fixed_display' : 'Upgrade to version 8.0.221 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.4',  'fixed_display' : 'Upgrade to version 11.0.4 or greater' },
  { 'min_version' : '12.0.0', 'fixed_version' : '12.0.2',  'fixed_display' : 'Upgrade to version 12.0.2 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
