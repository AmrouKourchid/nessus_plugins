#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000137353.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(184199);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id("CVE-2023-46747");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/11/21");
  script_xref(name:"CEA-ID", value:"CEA-2023-0056");
  script_xref(name:"IAVA", value:"2023-A-0591-S");

  script_name(english:"F5 Networks BIG-IP : BIG-IP Configuration utility unauthenticated remote code execution vulnerability (K000137353)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 13.1.5.1 + Hotfix-BIGIP-13.1.5.1.0.20.2-ENG /
14.1.5.6 +Hotfix-BIGIP-14.1.5.6.0.10.6-ENG / 15.1.10.2 + Hotfix-BIGIP-15.1.10.2.0.44.2-ENG / 16.1.4.1 + Hotfix-
BIGIP-16.1.4.1.0.50.5-ENG / 17.1.0.3 + Hotfix-BIGIP-17.1.0.3.0.75.4-ENG / 17.1.1 + Hotfix-BIGIP-17.1.1.0.2.6-ENG. It is,
therefore, affected by a vulnerability as referenced in the K000137353 advisory.

  - Undisclosed requests may bypass configuration utility authentication, allowing an attacker with network
    access to the BIG-IP system through the management port and/or self IP addresses to execute arbitrary
    system commands. Note: Software versions which have reached End of Technical Support (EoTS) are not
    evaluated (CVE-2023-46747)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000137353");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K000137353.");
  script_set_attribute(attribute:"workaround_type", value:"config_change");
  script_set_attribute(attribute:"workaround", value:
"F5 lists a workaround with instructions listed at https://my.f5.com/manage/s/article/K000137353 that can be achieved using
the following steps:

  1. Download, Configure, and Run Mitigation Script provided in the advisory
  2. Ensure that httpd is properly reset.

Note that Tenable always advises that you upgrade a system if possible, 
and all steps listed here are mitigation steps provided by F5. 
Tenable is not responsible for any negative effects that may occur from enacting this workaround.");
  script_set_attribute(attribute:"workaround_publication_date", value:"2023/10/26");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include('f5_func.inc');
include('local_detection_nix.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

# we are not checking the temporary mitigations that block the configuration utility
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var sol = 'K000137353';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.0.2.6','17.1.0.3.0.75.4','16.1.4.1.0.50.5','15.1.10.2.0.44.2','14.1.5.6.0.10.6','13.1.5.1.0.20.2'
    ],
  },
  'APM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.0.2.6','17.1.0.3.0.75.4','16.1.4.1.0.50.5','15.1.10.2.0.44.2','14.1.5.6.0.10.6','13.1.5.1.0.20.2'
    ],
  },
  'ASM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.0.2.6','17.1.0.3.0.75.4','16.1.4.1.0.50.5','15.1.10.2.0.44.2','14.1.5.6.0.10.6','13.1.5.1.0.20.2'
    ],
  },
  'DNS': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.0.2.6','17.1.0.3.0.75.4','16.1.4.1.0.50.5','15.1.10.2.0.44.2','14.1.5.6.0.10.6','13.1.5.1.0.20.2'
    ],
  },
  'GTM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.0.2.6','17.1.0.3.0.75.4','16.1.4.1.0.50.5','15.1.10.2.0.44.2','14.1.5.6.0.10.6','13.1.5.1.0.20.2'
    ],
  },
  'LTM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.0.2.6','17.1.0.3.0.75.4','16.1.4.1.0.50.5','15.1.10.2.0.44.2','14.1.5.6.0.10.6','13.1.5.1.0.20.2'
    ],
  },
  'PEM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.0.2.6','17.1.0.3.0.75.4','16.1.4.1.0.50.5','15.1.10.2.0.44.2','14.1.5.6.0.10.6','13.1.5.1.0.20.2'
    ],
  },
  'PSM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.0.2.6','17.1.0.3.0.75.4','16.1.4.1.0.50.5','15.1.10.2.0.44.2','14.1.5.6.0.10.6','13.1.5.1.0.20.2'
    ],
  },
  'WOM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.0.2.6','17.1.0.3.0.75.4','16.1.4.1.0.50.5','15.1.10.2.0.44.2','14.1.5.6.0.10.6','13.1.5.1.0.20.2'
    ],
  }
};

function mitigation_is_applied()
{
  # cannot use ldnix::init_plugin() here becasue it audits out of Host/uname is not set 
  enable_ssh_wrappers();
  info_connect(exit_on_fail:TRUE);

  var cmd = "grep -m1 -ioE '(required)?secret.*' /config/httpd/conf.d/proxy_ajp.conf /etc/tomcat/server.xml";
  var out = ldnix::run_cmd_template_wrapper(template:cmd);

  if (info_t == INFO_SSH) ssh_close_connection();

  var proxy_secret = pregmatch(pattern:'/config/httpd/conf.d/proxy_ajp.conf:secret=([0-9a-fA-F]+)', string:out);
  var tomcat_secret = pregmatch(pattern:'/etc/tomcat/server.xml:requiredSecret="([0-9a-fA-F]+)', string:out);

  if (empty_or_null(proxy_secret) || empty_or_null(proxy_secret[1]) || empty_or_null(tomcat_secret) || empty_or_null(tomcat_secret[1]))
    return FALSE;

  proxy_secret = proxy_secret[1];
  tomcat_secret = tomcat_secret[1];

  if (len(proxy_secret) != 40 || len(tomcat_secret) != 40)
    return FALSE;

  if (proxy_secret == tomcat_secret)
    return TRUE;
  else
    return FALSE;
}

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (mitigation_is_applied())
    audit(AUDIT_OS_CONF_NOT_VULN, 'F5 Networks BIG-IP');

  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
}
else
{
  var tested = bigip_get_tested_modules();
  var audit_extra = 'For BIG-IP module(s) ' + tested + ',';
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, 'running any of the affected modules');
}
