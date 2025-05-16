#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
# @NOAGENT@
# @DEPRECATED@
#
# Disabled on 2023/11/14. Deprecated by f5_bigip_SOL000137365.nasl and f5_bigip_SOL000137353.nasl
##

include('compat.inc');

if (description)
{
  script_id(183976);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/20");

  script_cve_id("CVE-2023-46747", "CVE-2023-46748");
  script_xref(name:"CEA-ID", value:"CEA-2023-0056");
  script_xref(name:"IAVA", value:"2023-A-0537");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/11/21");
  script_xref(name:"IAVA", value:"2023-A-0591");

  script_name(english:"F5 Networks BIG-IP : Multiple Vulnerabilities (K000137353, K000137365) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is potentially affected by multiple vulnerabilities as
referenced in the K000137353 and K000137365 advisories:

  - K000137353: BIG-IP Configuration utility unauthenticated remote code execution vulnerability (CVE-2023-46747)

  - K000137365: BIG-IP Configuration utility authenticated SQL injection vulnerability (CVE-2023-46748)

This plugin has been deprecated. Use f5_bigip_SOL000137353.nasl (184199) and f5_bigip_SOL000137365.nasl (184217) instead.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000137353");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000137365");
  # https://www.praetorian.com/blog/refresh-compromising-f5-big-ip-with-request-smuggling-cve-2023-46747/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8c050ad");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46747");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'F5 BIG-IP TMUI AJP Smuggling RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use f5_bigip_SOL000137353.nasl (184199) and f5_bigip_SOL000137365.nasl (184217) instead.');
