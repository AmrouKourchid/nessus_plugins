#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99588);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2017-3509",
    "CVE-2017-3511",
    "CVE-2017-3512",
    "CVE-2017-3514",
    "CVE-2017-3526",
    "CVE-2017-3533",
    "CVE-2017-3539",
    "CVE-2017-3544"
  );
  script_bugtraq_id(
    97727,
    97729,
    97731,
    97733,
    97737,
    97740,
    97745,
    97752
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 6 Update 151, 7 Update 141,
or 8 Update 131. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2017-3509)

  - An unspecified flaw exists in the JCE subcomponent that
    allows a local attacker to gain elevated privileges.
    This vulnerability does not affect Java SE version 6.
    (CVE-2017-3511)

  - An unspecified flaw exists in the AWT subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. This vulnerability does not
    affect Java SE version 6. (CVE-2017-3512)

  - An unspecified flaw exists in the AWT subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-3514)

  - An unspecified flaw exists in the JAXP subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3526)

  - Multiple unspecified flaws exist in the Networking
    subcomponent that allow an unauthenticated, remote
    attacker to gain update, insert, or delete access to
    unauthorized data. (CVE-2017-3533, CVE-2017-3544)

  - An unspecified flaw exists in the Security subcomponent
    that allows an unauthenticated, remote attacker to gain
    update, insert, or delete access to unauthorized data.
    (CVE-2017-3539)");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02dc6498");
  # http://www.oracle.com/technetwork/java/javase/8u131-relnotes-3565278.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce35fa3a");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb4db3c7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 6 Update 151 / 7 Update 141 / 8 Update 131
or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3514");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 6u151, 7u141, 8u131
var constraints = [
  { 'min_version' : '6.0.0',  'fixed_version' : '6.0.151', 'fixed_display' : 'Upgrade to version 6.0.151 or greater' },
  { 'min_version' : '7.0.0',  'fixed_version' : '7.0.141', 'fixed_display' : 'Upgrade to version 7.0.141 or greater' },
  { 'min_version' : '8.0.0',  'fixed_version' : '8.0.131', 'fixed_display' : 'Upgrade to version 8.0.131 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
