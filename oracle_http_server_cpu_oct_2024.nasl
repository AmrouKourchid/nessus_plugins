#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209278);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2024-2511",
    "CVE-2024-4603",
    "CVE-2024-4741",
    "CVE-2024-28182"
  );
  script_xref(name:"IAVA", value:"2024-A-0652-S");

  script_name(english:"Oracle HTTP Server (October 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of HTTP Server installed on the remote host are affected by multiple vulnerabilities as referenced in the
October 2024 CPU advisory.

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: Web Listener
    (OpenSSL)). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via TLS to compromise Oracle HTTP Server. Successful attacks
    of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of Oracle HTTP Server. (CVE-2024-2511, CVE-2024-4603, CVE-2024-4741)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: Plugins (Nghttp2)). 
    The supported version that is affected is 14.1.1.0.0. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via HTTP/2 to compromise Oracle HTTP Server. 
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial 
    denial of service (partial DOS) of Oracle HTTP Server. (CVE-2024-28182)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

var install = branch(install_list, key:TRUE, value:TRUE);

var patches = make_array();

patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.240906', 'patch', '37033394');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);
