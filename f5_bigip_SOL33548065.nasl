#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K33548065.
#
# @NOAGENT@
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159281);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id("CVE-2018-12536");

  script_name(english:"F5 Networks BIG-IP : Eclipse Jetty vulnerability (K33548065)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 15.1.9 / 16.1.4 / 17.1.1. It is, therefore,
affected by a vulnerability as referenced in the K33548065 advisory.

    In Eclipse Jetty Server, all 9.x versions, on webapps deployed using default Error Handling, when an
    intentionally bad query arrives that doesn't match a dynamic url-pattern, and is eventually handled by the
    DefaultServlet's static file serving, the bad characters can trigger a java.nio.file.InvalidPathException
    which includes the full path to the base resource directory that the DefaultServlet and/or webapp is
    using. If this InvalidPathException is then handled by the default Error Handler, the InvalidPathException
    message is included in the error response, revealing the full server path to the requesting
    system.(CVE-2018-12536)ImpactAn authenticated user can see the back-end directory, which should not be
    accessed through remote access.

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K33548065");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K33548065.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12536");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/29");

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

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var sol = 'K33548065';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'PSM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'SSL-Orchestrator': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'WOM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'iAppsLX': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
    ],
  },
  'iRulesLX': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '17.1.1','16.1.4','15.1.9'
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
