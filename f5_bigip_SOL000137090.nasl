#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000137090.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(182422);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/21");

  script_cve_id("CVE-2018-12121", "CVE-2018-12122", "CVE-2018-12123");

  script_name(english:"F5 Networks BIG-IP : Node.js vulnerabilities (K000137090)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the K000137090 advisory.

    CVE-2018-12121Node.js: All versions prior to Node.js 6.15.0, 8.14.0, 10.14.0 and 11.3.0: Denial of Service
    with large HTTP headers: By using a combination of many requests with maximum sized headers (almost 80 KB
    per connection), and carefully timed completion of the headers, it is possible to cause the HTTP server to
    abort from heap allocation failure. Attack potential is mitigated by the use of a load balancer or other
    proxy layer.CVE-2018-12122Node.js: All versions prior to Node.js 6.15.0, 8.14.0, 10.14.0 and 11.3.0:
    Slowloris HTTP Denial of Service: An attacker can cause a Denial of Service (DoS) by sending headers very
    slowly keeping HTTP or HTTPS connections and associated resources alive for a long period of
    time.CVE-2018-12123Node.js: All versions prior to Node.js 6.15.0, 8.14.0, 10.14.0 and 11.3.0: Hostname
    spoofing in URL parser for javascript protocol: If a Node.js application is using url.parse() to determine
    the URL hostname, that hostname can be spoofed by using a mixed case javascript: (e.g. javAscript:)
    protocol (other protocols are not affected). If security decisions are made about the URL based on the
    hostname, they may be incorrect.

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000137090");
  script_set_attribute(attribute:"solution", value:
"The vendor has acknowledged the vulnerability, but no solution has been provided.
Refer to the vendor for remediation guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12123");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/02");

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

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K000137090';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'APM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'ASM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'DNS': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'GTM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'LTM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'PEM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'PSM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'SSL-Orchestrator': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'WOM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'iAppsLX': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'iRulesLX': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.6','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
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
