#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96628);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2016-2183",
    "CVE-2016-5546",
    "CVE-2016-5547",
    "CVE-2016-5548",
    "CVE-2016-5549",
    "CVE-2016-5552",
    "CVE-2016-8328",
    "CVE-2017-3231",
    "CVE-2017-3241",
    "CVE-2017-3252",
    "CVE-2017-3253",
    "CVE-2017-3259",
    "CVE-2017-3260",
    "CVE-2017-3261",
    "CVE-2017-3262",
    "CVE-2017-3272",
    "CVE-2017-3289"
  );
  script_bugtraq_id(
    92630,
    95488,
    95498,
    95506,
    95509,
    95512,
    95521,
    95525,
    95530,
    95533,
    95559,
    95563,
    95566,
    95570,
    95576,
    95578,
    95581
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2017 CPU) (SWEET32)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 121, 7 Update 131,
or 6 Update 141. It is, therefore, affected by multiple
vulnerabilities :

  - A vulnerability exists in the Libraries subcomponent,
    known as SWEET32, in the 3DES and Blowfish algorithms
    due to the use of weak 64-bit block ciphers by default.
    A man-in-the-middle attacker who has sufficient
    resources can exploit this vulnerability, via a
    'birthday' attack, to detect a collision that leaks the
    XOR between the fixed secret and a known plaintext,
    allowing the disclosure of the secret text, such as
    secure HTTPS cookies, and possibly resulting in the
    hijacking of an authenticated session. (CVE-2016-2183)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2016-5546)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2016-5547)

  - Multiple unspecified flaws exist in the Libraries
    subcomponent that allow an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5548, CVE-2016-5549)

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2016-5552)

  - An unspecified flaw exists in the Mission Control
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2016-8328)

  - Multiple unspecified flaws exist in the Networking
    subcomponent that allow an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2017-3231, CVE-2017-3261)

  - An unspecified flaw exists in the RMI subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-3241)

  - An unspecified flaw exists in the JAAS subcomponent that
    allows an unauthenticated, remote attacker to impact
    integrity. (CVE-2017-3252)

  - An unspecified flaw exists in the 2D subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3253)

  - An unspecified flaw exists in the Deployment
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2017-3259)

  - An unspecified flaw exists in the AWT subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2017-3260)

  - An unspecified flaw exists in the Java Mission Control
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2017-3262)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-3272)

  - An unspecified flaw exists in the Hotspot subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-3289)

Note that CVE-2017-3241 can only be exploited by supplying data to
APIs in the specified component without using untrusted Java Web Start
applications or untrusted Java applets, such as through a web service.
Note that CVE-2016-2183, CVE-2016-5546, CVE-2016-5547, CVE-2016-5552,
CVE-2017-3252, and CVE-2017-3253 can be exploited through sandboxed
Java Web Start applications and sandboxed Java applets. They can also
be exploited by supplying data to APIs in the specified component
without using sandboxed Java Web Start applications or sandboxed Java
applets, such as through a web service.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?951bfdb7");
  # http://www.oracle.com/technetwork/java/javase/8u121-relnotes-3315208.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3776cd3");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 121 / 7 Update 131 / 6 Update
141 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3289");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/19");

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
# 6u141, 7u131, 8u121
var constraints = [
  { 'min_version' : '6.0.0',  'fixed_version' : '6.0.141', 'fixed_display' : 'Upgrade to version 6.0.141 or greater' },
  { 'min_version' : '7.0.0',  'fixed_version' : '7.0.131', 'fixed_display' : 'Upgrade to version 7.0.131 or greater' },
  { 'min_version' : '8.0.0',  'fixed_version' : '8.0.121', 'fixed_display' : 'Upgrade to version 8.0.121 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
