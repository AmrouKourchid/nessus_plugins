#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118227);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/20");

  script_cve_id(
    "CVE-2018-3136",
    "CVE-2018-3139",
    "CVE-2018-3149",
    "CVE-2018-3150",
    "CVE-2018-3157",
    "CVE-2018-3169",
    "CVE-2018-3180",
    "CVE-2018-3183",
    "CVE-2018-3209",
    "CVE-2018-3211",
    "CVE-2018-3214",
    "CVE-2018-13785"
  );
  script_bugtraq_id(
    105587,
    105590,
    105591,
    105595,
    105597,
    105599,
    105601,
    105602,
    105608,
    105615,
    105617,
    105622
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2018 CPU) (Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 11 Update 1, 8 Update 191,
7 Update 201, or 6 Update 211. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified vulnerability in the Java SE Embedded
    component of Oracle Java SE in the Deployment (libpng)
    subcomponent could allow an unauthenticated, remote
    attacker with network access via HTTP to compromise
    Java SE. (CVE-2018-13785)
 
  - An unspecified vulnerability in the Java SE Embedded
    component of Oracle Java SE in the Hotspot subcomponent
    that could allow an unauthenticated, remote attacker
    with network access via multiple protocols to compromise
    Java SE (CVE-2018-3169)

  - An unspecified vulnerability in the Java SE component of
    Oracle Java SE in the JavaFX subcomponent could allow an
    unauthenticated, remote attacker with network access via
    multiple protocols to compromise Java SE.
    (CVE-2018-3209)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded, and JRockit component of Oracle Java SE in
    the JNDI subcomponent could allow an unauthenticated,
    remote attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded, and
    JRockit. (CVE-2018-3149)
    
  - An unspecified vulnerability in the Java SE, Java SE
    Embedded, JRockit component of Oracle Java SE in the
    JSSE subcomponent could allow an unauthenticated,
    remote attacker with network access via SSL/TLS to
    compromise Java SE, Java SE Embedded, or JRockit.
    (CVE-2018-3180)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded component of Oracle Java SE in the Networking
    subcomponent could allow an unauthenticated, remote
    attacker with network access via multiple protocols to
    compromise Java SE or Java SE Embedded. (CVE-2018-3139)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded, JRockit component of Oracle Java SE in the
    Scripting subcomponent could allow an unauthenticated,
    remote attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded, or
    JRockit. (CVE-2018-3183)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded component of Oracle Java SE in the Security
    subcomponent could allow an unauthenticated, remote
    attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. (CVE-2018-3136)

  - An unspecified vulnerability in the Java SE, Java SE
    Embedded component of Oracle Java SE in the
    Serviceability subcomponent could allow a low privileged
    attacker with logon to the infrastructure where Java SE,
    Java SE Embedded executes to compromise Java SE, Java SE
    Embedded. (CVE-2018-3211)

  - An unspecified vulnerability in the Java SE component of
    Oracle Java SE in the Sound subcomponent could allow an
    unauthenticated, remote attacker with network access via
    multiple protocols to compromise Java SE.
    (CVE-2018-3157)

  - An unspecified vulnerability in the Java SE component of
    Oracle Java SE in the Utility subcomponent could allow an
    unauthenticated, remote attacker with network access via
    multiple protocols to compromise Java SE.
    (CVE-2018-3150)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?705136d8");
  # https://www.oracle.com/technetwork/java/javase/11-0-1-relnotes-5032023.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?278f2590");
  # https://www.oracle.com/technetwork/java/javase/8u191-relnotes-5032181.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adc8ef52");
  # https://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcacca");
  # https://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de812f33");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 11 Update 1, 8 Update 191 / 7 Update 201 /
6 Update 211 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.211', 'fixed_display' : 'Upgrade to version 6.0.211 or greater' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.201', 'fixed_display' : 'Upgrade to version 7.0.201 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.191', 'fixed_display' : 'Upgrade to version 8.0.191 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.1', 'fixed_display' : 'Upgrade to version 11.0.1 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
