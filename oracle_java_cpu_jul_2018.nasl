#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111163);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/27");

  script_cve_id(
    "CVE-2018-2938",
    "CVE-2018-2940",
    "CVE-2018-2941",
    "CVE-2018-2942",
    "CVE-2018-2952",
    "CVE-2018-2964",
    "CVE-2018-2972",
    "CVE-2018-2973"
  );
  script_bugtraq_id(
    104765,
    104768,
    104773,
    104774,
    104775,
    104780,
    104781,
    104782
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 10 Update 2, 8 Update 181,
7 Update 191, or 6 Update 201. It is, therefore, affected by
multiple vulnerabilities related to the following components :

  - Concurrency. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2952)

  - Deployment. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2964)

  - JSSE. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2973)

  - Java DB. A difficult to exploit vulnerability allows an
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. (CVE-2018-2938)

  - JavaFX. A difficult to exploit vulnerability allows an
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. (CVE-2018-2941)

  - Libraries. An easily exploitable vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. (CVE-2018-2940)

  - Security. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2972)

  - Windows DLL. A difficult to exploit vulnerability allows
    an unauthenticated attacker with network access via
    multiple protocols to compromise Java SE (CVE-2018-2942)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbb3b1db");
  # https://www.oracle.com/technetwork/java/javase/10-0-2-relnotes-4477557.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a11ccea");
  # https://www.oracle.com/technetwork/java/javase/8u181-relnotes-4479407.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c975c0b");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 10 Update 2, 8 Update 181 / 7 Update 191 /
6 Update 201 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 6u201, 7u191, 8u181, 10u2
var constraints = [
  { 'min_version' : '6.0.0',  'fixed_version' : '6.0.201', 'fixed_display' : 'Upgrade to version 6.0.201 or greater' },
  { 'min_version' : '7.0.0',  'fixed_version' : '7.0.191', 'fixed_display' : 'Upgrade to version 7.0.191 or greater' },
  { 'min_version' : '8.0.0',  'fixed_version' : '8.0.181', 'fixed_display' : 'Upgrade to version 8.0.181 or greater' },
  { 'min_version' : '10.0.0', 'fixed_version' : '10.0.2',  'fixed_display' : 'Upgrade to version 10.0.2 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);