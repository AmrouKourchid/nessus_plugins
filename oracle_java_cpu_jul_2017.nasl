#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101843);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2017-10053",
    "CVE-2017-10067",
    "CVE-2017-10074",
    "CVE-2017-10078",
    "CVE-2017-10081",
    "CVE-2017-10086",
    "CVE-2017-10087",
    "CVE-2017-10089",
    "CVE-2017-10090",
    "CVE-2017-10096",
    "CVE-2017-10101",
    "CVE-2017-10102",
    "CVE-2017-10104",
    "CVE-2017-10105",
    "CVE-2017-10107",
    "CVE-2017-10108",
    "CVE-2017-10109",
    "CVE-2017-10110",
    "CVE-2017-10111",
    "CVE-2017-10114",
    "CVE-2017-10115",
    "CVE-2017-10116",
    "CVE-2017-10117",
    "CVE-2017-10118",
    "CVE-2017-10121",
    "CVE-2017-10125",
    "CVE-2017-10135",
    "CVE-2017-10145",
    "CVE-2017-10176",
    "CVE-2017-10193",
    "CVE-2017-10198",
    "CVE-2017-10243"
  );
  script_bugtraq_id(
    99643,
    99659,
    99662,
    99670,
    99674,
    99703,
    99706,
    99707,
    99712,
    99719,
    99726,
    99731,
    99734,
    99752,
    99756,
    99774,
    99782,
    99788,
    99797,
    99804,
    99809,
    99818,
    99827,
    99832,
    99835,
    99839,
    99842,
    99846,
    99847,
    99851,
    99853,
    99854
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 141, 7 Update 151,
or 6 Update 161. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the 2D component that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-10053)

  - Multiple unspecified flaws exist in the Security
    component that allow an unauthenticated, remote attacker
    to execute arbitrary code. (CVE-2017-10067,
    CVE-2017-10116)

  - An unspecified flaw exists in the Hotspot component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-10074)

  - An unspecified flaw exists in the Scripting component
    that allows an authenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-10078)

  - An unspecified flaw exists in the Hotspot component that
    allows an unauthenticated, remote attacker to impact
    integrity. (CVE-2017-10081)

  - Multiple unspecified flaws exist in the JavaFX component
    that allow an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-10086, CVE-2017-10114)

  - Multiple unspecified flaws exist in the Libraries
    component that allow an unauthenticated, remote attacker
    to execute arbitrary code. (CVE-2017-10087,
    CVE-2017-10090, CVE-2017-10111)

  - An unspecified flaw exists in the ImageIO component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-10089)

  - Multiple unspecified flaws exist in the JAXP component
    that allow an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-10096, CVE-2017-10101)

  - Multiple unspecified flaws exist in the RMI component
    that allow an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-10102, CVE-2017-10107)

  - Multiple unspecified flaws exist in the Server component
    of the Java Advanced Management Console that allow an
    authenticated, remote attacker to impact
    confidentiality, integrity, and availability.
    (CVE-2017-10104, CVE-2017-10145)

  - An unspecified flaw exists in the Deployment component
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2017-10105)

  - Multiple unspecified flaws exist in the Serialization
    component that allow an unauthenticated, remote attacker
    to exhaust available memory, resulting in a denial of
    service condition. (CVE-2017-10108, CVE-2017-10109)

  - An unspecified flaw exists in the AWT component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-10110)

  - Multiple unspecified flaws exist in the JCE component
    that allow an unauthenticated, remote attacker to
    disclose sensitive information. (CVE-2017-10115,
    CVE-2017-10118, CVE-2017-10135)

  - An unspecified flaw exists in the Server component of
    the Java Advanced Management Console that allows an
    unauthenticated, remote attacker to disclose sensitive
    information. (CVE-2017-10117)

  - An unspecified flaw exists in the Server component of
    the Java Advanced Management Console that allows an
    unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-10121)

  - An unspecified flaw exists in the Deployment component
    that allows a local attacker to impact confidentiality,
    integrity, and availability. (CVE-2017-10125)

  - Multiple unspecified flaws exist in the Security
    component that allow an unauthenticated, remote attacker
    to disclose sensitive information. (CVE-2017-10176,
    CVE-2017-10193, CVE-2017-10198)

  - An unspecified flaw exists in the JAX-WS component that
    allows an unauthenticated, remote attacker to impact
    confidentiality and availability. (CVE-2017-10243)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76f5def7");
  # http://www.oracle.com/technetwork/java/javase/8u141-relnotes-3720385.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?755142b1");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 141 / 7 Update 151 / 6 Update
161 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10111");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# 6u161, 7u151, 8u141
var constraints = [
  { 'min_version' : '6.0.0',  'fixed_version' : '6.0.161', 'fixed_display' : 'Upgrade to version 6.0.161 or greater' },
  { 'min_version' : '7.0.0',  'fixed_version' : '7.0.151', 'fixed_display' : 'Upgrade to version 7.0.151 or greater' },
  { 'min_version' : '8.0.0',  'fixed_version' : '8.0.141', 'fixed_display' : 'Upgrade to version 8.0.141 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
