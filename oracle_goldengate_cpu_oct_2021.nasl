#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154342);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2011-4969",
    "CVE-2012-6708",
    "CVE-2015-9251",
    "CVE-2018-10237",
    "CVE-2019-3738",
    "CVE-2019-3739",
    "CVE-2019-3740",
    "CVE-2019-11358",
    "CVE-2019-17566",
    "CVE-2020-8908",
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2020-11987"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");

  script_name(english:"Oracle GoldenGate (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The All Supported Versions versions of GoldenGate installed on the remote host are affected by multiple vulnerabilities
as referenced in the October 2021 CPU advisory.

  - Vulnerability in Oracle GoldenGate (component: Install (Dell BSAFE Crypto-J)). The supported version that is
    affected is Prior to 19.1.0.0.0.210420. Easily exploitable vulnerability allows unauthenticated attacker with
    network access via Oracle Net to compromise Oracle GoldenGate. Successful attacks require human interaction
    from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Oracle GoldenGate accessible data. (CVE-2019-3740)

  - Security-in-Depth issue in Oracle GoldenGate (component: Install (jQuery)). This vulnerability cannot be
    exploited in the context of this product. (CVE-2020-11023)
  
  - Security-in-Depth issue in Oracle GoldenGate (component: General (Apache Batik)). This vulnerability cannot 
    be exploited in the context of this product. (CVE-2020-11987)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11987");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:goldengate");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_goldengate_installed.nbin");
  script_require_keys("Oracle/GoldenGate/Installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_goldengate::get_app_info();

var constraints = [
  {
    'min_version'   : '19.1' ,
    'fixed_version' : '19.1.0.0.211019',
    'fixed_display' : '19.1.0.0.211019 (33376981 / 33376978 / 33376975 / 33376964)'
  }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
