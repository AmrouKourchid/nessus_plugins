#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183397);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/19");

  script_cve_id(
    "CVE-2023-2976",
    "CVE-2023-3817",
    "CVE-2023-20863",
    "CVE-2023-34034",
    "CVE-2023-41080"
  );

  script_name(english:"Oracle MySQL Enterprise Monitor (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Enterprise Monitor installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2023 CPU advisory.

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (Apache Struts)). Supported versions that are affected are 8.0.34 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Enterprise Monitor. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Enterprise Monitor. (CVE-2023-34396)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Centralized
    Thirdparty Jars (Google Guava)). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0.
    Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where
    Oracle WebLogic Server executes to compromise Oracle WebLogic Server. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Oracle WebLogic Server accessible data as well as unauthorized access to critical data or complete access
    to all Oracle WebLogic Server accessible data. (CVE-2023-2976)

  - Vulnerability in the Oracle SD-WAN Edge product of Oracle Communications (component: Management (Spring
    Framework)). The supported version that is affected is 9.1.1.5.0. Easily exploitable vulnerability allows
    low privileged attacker with network access via HTTP to compromise Oracle SD-WAN Edge. Successful attacks
    of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of Oracle SD-WAN Edge. (CVE-2023-20863)

  - Using ** as a pattern in Spring Security configuration for WebFlux creates a mismatch in pattern
    matching between Spring Security and Spring WebFlux, and the potential for a security bypass.
    (CVE-2023-34034)

  - Issue summary: Checking excessively long DH keys or parameters may be very slow. Impact summary:
    Applications that use the functions DH_check(), DH_check_ex() or EVP_PKEY_param_check() to check a DH key
    or DH parameters may experience long delays. Where the key or parameters that are being checked have been
    obtained from an untrusted source this may lead to a Denial of Service. The function DH_check() performs
    various checks on DH parameters. After fixing CVE-2023-3446 it was discovered that a large q parameter
    value can also trigger an overly long computation during some of these checks. A correct q value, if
    present, cannot be larger than the modulus p parameter, thus it is unnecessary to perform these checks if
    q is larger than p. An application that calls DH_check() and supplies a key or parameters obtained from an
    untrusted source could be vulnerable to a Denial of Service attack. The function DH_check() is itself
    called by a number of other OpenSSL functions. An application calling any of those other functions may
    similarly be affected. The other functions affected by this are DH_check_ex() and EVP_PKEY_param_check().
    Also vulnerable are the OpenSSL dhparam and pkeyparam command line applications when using the -check
    option. The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS
    providers are not affected by this issue. (CVE-2023-3817)

  - URL Redirection to Untrusted Site ('Open Redirect') vulnerability in FORM authentication feature Apache
    Tomcat.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through
    10.0.12, from 9.0.0-M1 through 9.0.79 and from 8.5.0 through 8.5.92. The vulnerability is limited to the
    ROOT (default) web application. (CVE-2023-41080)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl", "oracle_mysql_enterprise_monitor_local_nix_detect.nbin", "oracle_mysql_enterprise_monitor_local_detect.nbin", "macosx_mysql_enterprise_monitor_installed.nbin");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MySQL Enterprise Monitor');

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.36' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
