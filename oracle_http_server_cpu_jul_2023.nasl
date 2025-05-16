#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178623);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/18");

  script_cve_id(
    "CVE-2022-43680",
    "CVE-2023-23914",
    "CVE-2023-23915",
    "CVE-2023-23916",
    "CVE-2023-25690"
  );
  script_xref(name:"IAVA", value:"2023-A-0365-S");
  script_xref(name:"IAVA", value:"2023-A-0558");
  script_xref(name:"IAVA", value:"2023-A-0560-S");

  script_name(english:"Oracle HTTP Server (Jul 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host are affected by multiple vulnerabilities as referenced
in the Jul 2023 CPU advisory.

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: Thirdparty
  (LibExpat)). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows
  unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server. Successful attacks
  of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of Oracle HTTP Server. (CVE-2022-43680)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: SSL Module (cURL))
  . The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows
  unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server. Successful attacks
  of this vulnerability can result in unauthorized creation, deletion or modification access to critical data
  or all Oracle HTTP Server accessible data as well as unauthorized access to critical data or complete access
  to all Oracle HTTP Server accessible data. (CVE-2023-23914)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: SSL Module (Apache
   HTTP Server)). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability
  allows unauthenticated attacker with network access via HTTPS to compromise Oracle HTTP Server. Successful
  attacks of this vulnerability can result in takeover of Oracle HTTP Server. (CVE-2023-25690)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25690");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

var install = branch(install_list, key:TRUE, value:TRUE);

var patches = make_array();
patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.230707', 'patch', '35577558');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);
