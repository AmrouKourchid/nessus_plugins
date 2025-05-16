#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193460);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/19");

  script_cve_id(
    "CVE-2022-25147",
    "CVE-2022-34381",
    "CVE-2023-24021",
    "CVE-2023-31122",
    "CVE-2023-46218",
    "CVE-2024-20991"
  );

  script_name(english:"Oracle HTTP Server (April 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of HTTP Server installed on the remote host are affected by multiple vulnerabilities as referenced in the
April 2024 CPU advisory:

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: Plugins (BSAFE Crypto-J)). 
    Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via TLS to compromise Oracle HTTP Server. Successful attacks of this 
    vulnerability can result in takeover of Oracle HTTP Server. (CVE-2022-34381)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: SSL Module (ModSecurity)). 
    The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated 
    attacker with network access via TLS to compromise Oracle HTTP Server. Successful attacks of this vulnerability 
    can result in unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server 
    accessible data. (CVE-2023-24021)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: Third Party (Apache HTTP 
    Server)). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server. Successful attacks of this 
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of 
    Oracle HTTP Server. (CVE-2023-31122)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34381");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

var install = branch(install_list, key:TRUE, value:TRUE);

var patches = make_array();

# 
# Prevent FP that has this release installed:
# 12c (latest patch) - 12.2.1.4.240115
# 
if (install[1] == "12.2.1.4.240115")
{
  patches = make_array();
  patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.240115', 'patch', '36187026');
  oracle_http_server_check_vuln(
    install : install,
    min_patches : patches,
    severity : SECURITY_HOLE
  );
}

#
# 12c releases; any releases < 12.2.1.4.240115 would be recommended to upgrade to 19c 12.2.1.4.240312
# Also checks 19c versions
#  
if (install[1] < "12.2.1.4.240115" || (install[1] > "12.2.1.4.240115" || install[1] > "12.2.1.4.240312"))
{
  patches = make_array();
  patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.240312', 'patch', '36393221');
  oracle_http_server_check_vuln(
    install : install,
    min_patches : patches,
    severity : SECURITY_HOLE
  );
}

