#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K63025104.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(132574);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2018-7160");

  script_name(english:"F5 Networks BIG-IP : NodeJS vulnerability (K63025104)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Node.js inspector, in 6.x and later is vulnerable to a DNS
rebinding attack which could be exploited to perform remote code
execution. An attack is possible from malicious websites open in a web
browser on the same computer, or another computer with network access
to the computer running the Node.js process. A malicious website could
use a DNS rebinding attack to trick the web browser to bypass
same-origin-policy checks and to allow HTTP connections to localhost
or to hosts on the local network. If a Node.js process with the debug
port active is running on localhost or on a host on the local network,
the malicious website could connect to it as a debugger, and get full
code execution access.(CVE-2018-7160)

Impact

An attacker usinga malicious website may be able to remotely perform
arbitrary code execution.

BIG-IP

This vulnerability isexposed when youlicenseand provisioniRulesLX
andinvoke Node.jsusing an iRule, or when you install iAppsLXanduse the
BIG-IP Configuration utility (GUI).

F5 SSL Orchestrator

This vulnerability is exposed when using the Configuration utility
(GUI) for F5 SSL Orchestrator.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K63025104");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K63025104.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K63025104';
var vmatrix = {
  'AFM': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
    ],
  },
  'AM': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
    ],
  },
  'APM': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
    ],
  },
  'ASM': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
    ],
  },
  'AVR': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
    ],
  },
  'DNS': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
    ],
  },
  'GTM': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
    ],
  },
  'LC': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
    ],
  },
  'LTM': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
    ],
  },
  'PEM': {
    'affected': [
      '14.1.0','14.0.0','13.1.0-13.1.2'
    ],
    'unaffected': [
      '14.1.0.6','14.0.0.5','13.1.3'
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
