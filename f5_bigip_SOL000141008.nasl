#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000141008.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(206826);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/30");

  script_cve_id("CVE-2024-3596");

  script_name(english:"F5 Networks BIG-IP : RADIUS authentication vulnerability (K000141008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 16.1.6 / 17.1.2 / Hotfix-
BIGIP-15.1.10.5.0.28.10-ENG.iso / Hotfix-BIGIP-16.1.5.1.0.13.7-ENG.iso / Hotfix-BIGIP-17.1.1.4.0.100.9-ENG.iso. It is,
therefore, affected by a vulnerability as referenced in the K000141008 advisory.

    RADIUS Protocol under RFC 2865 is susceptible to forgery attacks by a local attacker who can modify any
    valid Response (Access-Accept, Access-Reject, or Access-Challenge) to any other response using a chosen-
    prefix collision attack against MD5 Response Authenticator signature.(CVE-2024-3596)

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000141008");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K000141008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/R:A");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3596");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_iapps_lx");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_irules_lx");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_ssl_orchestrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

var sol = 'K000141008';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'APM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'ASM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'DNS': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'GTM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'LTM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'PEM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'PSM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'SSL-Orchestrator': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'WOM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'iAppsLX': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  },
  'iRulesLX': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.1.2','17.1.1.4.0.100.9','16.1.6','16.1.5.1.0.13.7','15.1.10.5.0.28.10'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
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
