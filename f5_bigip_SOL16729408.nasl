#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K16729408.
#
# @NOAGENT@
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154702);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id("CVE-2020-12049");

  script_name(english:"F5 Networks BIG-IP : D-Bus vulnerability (K16729408)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 15.1.4.1. It is, therefore, affected by a
vulnerability as referenced in the K16729408 advisory.

    An issue was discovered in dbus >= 1.3.0 before 1.12.18. The DBusServer in libdbus, as used in dbus-
    daemon, leaks file descriptors when a message exceeds the per-message file descriptor limit. A local
    attacker with access to the D-Bus system bus or another system service's private AF_UNIX socket could use
    this to make the system service reach its file descriptor limit, denying service to subsequent D-Bus
    clients.(CVE-2020-12049)ImpactA local attacker maycause a denial-of-service (DoS) attack or threaten the
    availability of the system.

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K16729408");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K16729408.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12049");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Settings/ParanoidReport", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var sol = 'K16729408';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'PSM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'SSL-Orchestrator': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'WOM': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'iAppsLX': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  },
  'iRulesLX': {
    'affected': [
      '17.0.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.4','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.4.1'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
