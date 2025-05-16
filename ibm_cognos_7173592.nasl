#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213274);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2018-12538",
    "CVE-2018-12545",
    "CVE-2019-10241",
    "CVE-2020-27216",
    "CVE-2021-28169",
    "CVE-2021-34428",
    "CVE-2022-29622",
    "CVE-2023-26048",
    "CVE-2023-26049",
    "CVE-2023-36479",
    "CVE-2023-38737",
    "CVE-2023-40167",
    "CVE-2023-41900",
    "CVE-2023-42282",
    "CVE-2023-44483",
    "CVE-2023-44487",
    "CVE-2023-46809",
    "CVE-2023-50312",
    "CVE-2023-51775",
    "CVE-2023-52428",
    "CVE-2024-21890",
    "CVE-2024-21891",
    "CVE-2024-21892",
    "CVE-2024-21896",
    "CVE-2024-22017",
    "CVE-2024-22019",
    "CVE-2024-22025",
    "CVE-2024-22329",
    "CVE-2024-25042",
    "CVE-2024-27270",
    "CVE-2024-29415"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVB", value:"2024-B-0196-S");

  script_name(english:"IBM Cognos Analytics 11.2.x < 11.2.4 FP4 / 12.0.x < 12.0.4 Multiple Vulnerabilities (7173592)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Cognos Analytics installed on the remote host is prior to 11.2.4 FP4 or 12.0.4. It is, therefore,
affected by multiple vulnerabilities as referenced in the 7173592 advisory.

  - An arbitrary file upload vulnerability in formidable v3.1.4 allows attackers to execute arbitrary code via 
    a crafted filename. NOTE: some third parties dispute this issue because the product has common use cases 
    in which uploading arbitrary files is the desired behavior. Also, there are configuration options in all 
    versions that can change the default behavior of how files are handled. Strapi does not consider this to 
    be a valid vulnerability. (CVE-2022-29622)

  - Node.js IP package could allow a remote attacker to execute arbitrary code on the system, caused by a 
    server-side request forgery flaw in the ip.isPublic() function. By sending a specially crafted request 
    using a hexadecimal representation of a private IP address, an attacker could exploit this vulnerability 
    to execute arbitrary code on the system and obtain sensitive information. (CVE-2023-42282)
  
  - Multiple vendors are vulnerable to a denial of service, caused by a flaw in handling multiplexed streams 
    in the HTTP/2 protocol. By sending numerous HTTP/2 requests and RST_STREAM frames over multiple streams, a 
    remote attacker could exploit this vulnerability to cause a denial of service due to server resource 
    consumption. (CVE-2023-44487)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7173592");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Cognos Analytics version 11.2.4 FP4 / 12.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29622");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-21896");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:cognos_analytics");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_cognos_analytics_web_detect.nbin");
  script_require_keys("installed_sw/IBM Cognos Analytics");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'IBM Cognos Analytics', port:port, webapp:TRUE);

var constraints = [
  {'min_version': '11.2.0', 'max_version': '11.2.3', 'fixed_display' : '11.2.4 FP4'},
  # AC detection does not pick up fix packs (FPs)
  {'equal': '11.2.4', 'fixed_display': '11.2.4 FP4', 'require_paranoia':TRUE},
  {'min_version': '12.0.0', 'fixed_version': '12.0.4'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
