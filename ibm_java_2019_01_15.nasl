#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160349);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/31");

  script_cve_id(
    "CVE-2018-11212",
    "CVE-2019-2422",
    "CVE-2019-2426",
    "CVE-2019-2449"
  );
  script_xref(name:"IAVA", value:"2019-A-0022-S");

  script_name(english:"IBM Java 7.0 < 7.0.10.40 / 7.1 < 7.1.4.40 / 8.0 < 8.0.5.30 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 7.0 < 7.0.10.40 / 7.1 < 7.1.4.40 / 8.0 < 8.0.5.30. It
is, therefore, affected by multiple vulnerabilities as referenced in the Oracle January 15 2019 CPU advisory.

  - An issue was discovered in libjpeg 9a and 9d. The alloc_sarray function in jmemmgr.c allows remote
    attackers to cause a denial of service (divide-by-zero error) via a crafted file. (CVE-2018-11212)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Libraries). Supported versions
    that are affected are Java SE: 7u201, 8u192 and 11.0.1; Java SE Embedded: 8u191. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Java SE. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of Java SE accessible
    data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2019-2422)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Networking). Supported versions
    that are affected are Java SE: 7u201, 8u192 and 11.0.1; Java SE Embedded: 8u191. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Java SE. Successful attacks of this vulnerability can result in unauthorized read access to a subset of
    Java SE accessible data. Note: This vulnerability applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service
    which supplies data to the APIs. (CVE-2019-2426)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Deployment). The supported version
    that is affected is Java SE: 8u192. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to
    Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2019-2449)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ13343");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ13344");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ13345");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ13346");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_January_15_2019_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0bba92b");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle January 15 2019 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2426");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_java_nix_installed.nbin", "ibm_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['IBM Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.40' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.40' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5.30' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
