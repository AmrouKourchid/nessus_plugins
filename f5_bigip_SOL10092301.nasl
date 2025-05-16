#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K10092301.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(127495);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2019-6471");

  script_name(english:"F5 Networks BIG-IP : BIND vulnerability (K10092301)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A race condition which may occur when discarding malformed packets can
result in BIND exiting due to a REQUIRE assertion failure in
dispatch.c. Versions affected: BIND 9.11.0 -> 9.11.7, 9.12.0 ->
9.12.4-P1, 9.14.0 -> 9.14.2. Also all releases of the BIND 9.13
development branch and version 9.15.0 of the BIND 9.15 development
branch and BIND Supported Preview Edition versions 9.11.3-S1 ->
9.11.7-S1. (CVE-2019-6471)

Impact

A remote attacker, who could cause the BIND resolver to perform
queries on a server, which responds deliberately with malformed
answers, can cause named to exit and result in a denial-of-service
(DoS) condition.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K10092301");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K10092301.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6471");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
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

var sol = 'K10092301';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'AM': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'APM': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'ASM': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'AVR': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'DNS': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'GTM': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'LC': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'LTM': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'PEM': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
    ],
  },
  'WAM': {
    'affected': [
      '15.0.0','14.1.0','14.0.0','13.1.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.4','11.5.2-11.5.9'
    ],
    'unaffected': [
      '15.1.0','15.0.1','14.1.2','14.0.1','13.1.3','12.1.5','11.6.5','11.5.10'
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
