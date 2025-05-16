#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189118);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/19");

  script_cve_id(
    "CVE-2021-33813",
    "CVE-2023-33201",
    "CVE-2023-42503",
    "CVE-2023-44483"
  );
  script_xref(name:"IAVA", value:"2024-A-0031");

  script_name(english:"Oracle WebCenter Portal Multiple Vulnerabilities (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Portal installed on the remote host is missing a security patch from the January 2024
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities:

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security Framework 
    (Bouncy Castle Java Library)). Easily exploitable vulnerability allows unauthenticated attacker with network access
    via LDAP to compromise Oracle WebCenter Portal. Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Oracle WebCenter Portal accessible data. (CVE-2023-33201)

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security Framework 
    (Apache Solr)). Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to 
    compromise Oracle WebCenter Portal. Successful attacks of this vulnerability can result in unauthorized ability to 
    cause a hang or frequently repeatable crash (complete DOS) of Oracle WebCenter Portal. (CVE-2021-33813)

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security Framework 
    (Apache Commons Compress)). Easily exploitable vulnerability allows unauthenticated attacker with logon to the 
    infrastructure where Oracle WebCenter Portal executes to compromise Oracle WebCenter Portal. Successful attacks 
    require human interaction from a person other than the attacker. Successful attacks of this vulnerability can 
    result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebCenter 
    Portal. (CVE-2023-42503)

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33813");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-44483");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_portal_installed.nbin");
  script_require_keys("installed_sw/Oracle WebCenter Portal");

  exit(0);
}

include('vcf_extras_oracle_webcenter_portal.inc');

var app_info = vcf::oracle_webcenter_portal::get_app_info();

var constraints = [
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.231121'}
];

vcf::oracle_webcenter_portal::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);