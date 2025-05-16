#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92517);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/20");

  script_cve_id(
    "CVE-2016-3458",
    "CVE-2016-3485",
    "CVE-2016-3498",
    "CVE-2016-3500",
    "CVE-2016-3503",
    "CVE-2016-3508",
    "CVE-2016-3511",
    "CVE-2016-3550",
    "CVE-2016-3552",
    "CVE-2016-3587",
    "CVE-2016-3598",
    "CVE-2016-3606",
    "CVE-2016-3610"
  );
  script_bugtraq_id(
    91904,
    91912,
    91918,
    91930,
    91945,
    91951,
    91956,
    91962,
    91972,
    91990,
    91996,
    92000,
    92006
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2016 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 101, 7 Update 111,
or 6 Update 121. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the CORBA subcomponent
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2016-3458)

  - An unspecified flaw exists in the Networking
    subcomponent that allows a local attacker to impact
    integrity. (CVE-2016-3485)

  - An unspecified flaw exists in the JavaFX subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2016-3498)

  - An unspecified flaw exists in the JAXP subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3500)

  - An unspecified flaw exists in the Install subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-3503)

  - An unspecified flaw exists in the JAXP subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3508)

  - An unspecified flaw exists in the Deployment
    subcomponent that allows a local attacker to gain
    elevated privileges. (CVE-2016-3511)

  - An unspecified flaw exists in the Hotspot subcomponent
    that allows an unauthenticated, remote attacker to
    disclose potentially sensitive information.
    (CVE-2016-3550)

  - An unspecified flaw exists in the Install subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-3552)

  - A flaw exists in the Hotspot subcomponent due to
    improper access to the MethodHandle::invokeBasic()
    function. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code. (CVE-2016-3587)

  - A flaw exists in the Libraries subcomponent within the
    MethodHandles::dropArguments() function that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-3598)

  - A flaw exists in the Hotspot subcomponent within the
    ClassVerifier::ends_in_athrow() function when handling
    bytecode verification. An unauthenticated, remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2016-3606)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2016-3610)");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e71b6836");
  # http://www.oracle.com/technetwork/java/javase/8u101-relnotes-3021761.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92867054");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html#R170_111
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6adbf356");
  # https://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html#R160_121
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81636e81");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 101 / 7 Update 111 / 6 Update
121 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.121', 'fixed_display' : 'Upgrade to version 6.0.121 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.111', 'fixed_display' : 'Upgrade to version 7.0.111 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.101', 'fixed_display' : 'Upgrade to version 8.0.101 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
