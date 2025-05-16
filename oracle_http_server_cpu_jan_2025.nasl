#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214582);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id(
    "CVE-2023-38709",
    "CVE-2023-49582",
    "CVE-2024-5535",
    "CVE-2024-6119",
    "CVE-2024-8096",
    "CVE-2024-38473",
    "CVE-2024-38475",
    "CVE-2024-40898",
    "CVE-2024-45490",
    "CVE-2024-45491",
    "CVE-2024-45492",
    "CVE-2025-21498"
  );
  script_xref(name:"IAVA", value:"2025-A-0047");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/05/22");

  script_name(english:"Oracle HTTP Server (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of HTTP Server installed on the remote host are affected by multiple vulnerabilities as referenced in the
January 2025 CPU advisory.

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: Core (LibExpat)). The 
    supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker 
    with network access via HTTP to compromise Oracle HTTP Server.  Successful attacks of this vulnerability can result 
    in takeover of Oracle HTTP Server. (CVE-2024-45492)

  - The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated 
    attacker with network access via HTTP to compromise Oracle HTTP Server.  Successful attacks of this vulnerability 
    can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server
    accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server 
    accessible data.(CVE-2023-38709)

  - The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle HTTP Server executes to compromise Oracle HTTP Server.  
    Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access 
    to all Oracle HTTP Server accessible data. CVSS 3.1 Base Score 5.5 (Confidentiality impacts)(CVE-2023-49582)

  - The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated 
    attacker with network access via HTTP to compromise Oracle HTTP Server.  Successful attacks of this vulnerability 
    can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server 
    accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server 
    accessible data (CVE-2024-38473)

  - The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated 
    attacker with network access via HTTP to compromise Oracle HTTP Server.  Successful attacks of this vulnerability 
    can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server 
    accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server 
    accessible data. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts). (CVE-2024-38475)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

var install = branch(install_list, key:TRUE, value:TRUE);

var patches = make_array();
patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.250103', 'patch', '37443574');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);
