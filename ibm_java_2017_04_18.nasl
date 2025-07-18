#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160359);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id(
    "CVE-2017-3509",
    "CVE-2017-3511",
    "CVE-2017-3512",
    "CVE-2017-3514",
    "CVE-2017-3533",
    "CVE-2017-3539",
    "CVE-2017-3544"
  );
  script_xref(name:"IAVA", value:"2017-A-0116-S");

  script_name(english:"IBM Java 6.0 < 6.0.16.45 / 6.1 < 6.1.8.45 / 7.0 < 7.0.10.5 / 7.1 < 7.1.4.5 / 8.0 < 8.0.4.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.45 / 6.1 < 6.1.8.45 / 7.0 < 7.0.10.5 / 7.1
< 7.1.4.5 / 8.0 < 8.0.4.5. It is, therefore, affected by multiple vulnerabilities as referenced in the Oracle April 18
2017 CPU advisory.

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Networking).
    Supported versions that are affected are Java SE: 6u141, 7u131 and 8u121; Java SE Embedded: 8u121.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data as well as
    unauthorized read access to a subset of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2017-3509)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: JCE).
    Supported versions that are affected are Java SE: 7u131 and 8u121; Java SE Embedded: 8u121; JRockit:
    R28.3.13. Difficult to exploit vulnerability allows unauthenticated attacker with logon to the
    infrastructure where Java SE, Java SE Embedded, JRockit executes to compromise Java SE, Java SE Embedded,
    JRockit. Successful attacks require human interaction from a person other than the attacker and while the
    vulnerability is in Java SE, Java SE Embedded, JRockit, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can result in takeover of Java SE, Java SE Embedded,
    JRockit. Note: Applies to client and server deployment of Java. This vulnerability can be exploited
    through sandboxed Java Web Start applications and sandboxed Java applets. It can also be exploited by
    supplying data to APIs in the specified Component without using sandboxed Java Web Start applications or
    sandboxed Java applets, such as through a web service. (CVE-2017-3511)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: AWT). Supported versions that are
    affected are Java SE: 7u131 and 8u121. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE. Successful attacks require human
    interaction from a person other than the attacker and while the vulnerability is in Java SE, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in takeover
    of Java SE. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to
    Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2017-3512)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: AWT). Supported versions that are
    affected are Java SE: 6u141, 7u131 and 8u121. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Java SE. Successful attacks require
    human interaction from a person other than the attacker and while the vulnerability is in Java SE, attacks
    may significantly impact additional products. Successful attacks of this vulnerability can result in
    takeover of Java SE. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2017-3514)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Networking). Supported versions that are affected are Java SE: 6u141, 7u131 and 8u121; Java SE Embedded:
    8u121; JRockit: R28.3.13. Difficult to exploit vulnerability allows unauthenticated attacker with network
    access via FTP to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete access to some of Java SE, Java SE Embedded, JRockit
    accessible data. Note: Applies to client and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications and sandboxed Java applets. It can also be
    exploited by supplying data to APIs in the specified Component without using sandboxed Java Web Start
    applications or sandboxed Java applets, such as through a web service. (CVE-2017-3533)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Security).
    Supported versions that are affected are Java SE: 6u141, 7u131 and 8u121; Java SE Embedded: 8u121.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2017-3539)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Networking). Supported versions that are affected are Java SE: 6u141, 7u131 and 8u121; Java SE Embedded:
    8u121; JRockit: R28.3.13. Difficult to exploit vulnerability allows unauthenticated attacker with network
    access via SMTP to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete access to some of Java SE, Java SE Embedded, JRockit
    accessible data. Note: Applies to client and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications and sandboxed Java applets. It can also be
    exploited by supplying data to APIs in the specified Component without using sandboxed Java Web Start
    applications or sandboxed Java applets, such as through a web service. (CVE-2017-3544)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV95261");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV95262");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV95263");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV95264");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV95265");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV95266");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV95267");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_April_18_2017_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cd4a76b");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle April 18 2017 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3514");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_java_nix_installed.nbin", "ibm_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['IBM Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.45' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.45' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.5' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.5' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.4.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
