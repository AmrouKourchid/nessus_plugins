#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183519);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/23");

  script_cve_id(
    "CVE-2023-2650",
    "CVE-2023-22019",
    "CVE-2023-28484",
    "CVE-2022-37436"
  );
  script_xref(name:"IAVA", value:"2023-A-0559");

  script_name(english:"Oracle HTTP Server (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host are affected by multiple vulnerabilities as referenced
in the October 2023 CPU advisory.

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: Web Listener). The 
    supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker 
    with network access via HTTP to compromise Oracle HTTP Server. Successful attacks of this vulnerability can result
    in unauthorized access to critical data or complete access to all Oracle HTTP Server accessible data. 
    (CVE-2023-22019)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: SSL Module (OpenSSL)). 
    The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated 
    attacker with network access via HTTPS to compromise Oracle HTTP Server. Successful attacks require human 
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in 
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle HTTP Server. 
    (CVE-2022-2650)

  - Vulnerability in the Oracle Communications Cloud Native Core Binding Support Function product of Oracle 
    Communications (component: Install/Upgrade (libxml2)). Supported versions that are affected are 23.1.0-23.1.7 
    and 23.2.0-23.2.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP 
    to compromise Oracle Communications Cloud Native Core Binding Support Function. Successful attacks require human 
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in 
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Communications Cloud 
    Native Core Binding Support Function. (CVE-2023-28484)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22019");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

var install = branch(install_list, key:TRUE, value:TRUE);

var patches = make_array();
patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.230922', 'patch', '35837445');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);