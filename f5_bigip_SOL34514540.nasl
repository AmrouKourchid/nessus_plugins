#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K34514540.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(118604);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id("CVE-2017-6138");

  script_name(english:"F5 Networks BIG-IP : TMM vulnerability (K34514540)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Malicious requests made to virtual servers with an HTTP profile can
cause the TMM to restart. The issue is exposed with BIG-IP APM
profiles, regardless of settings. The issue is also exposed with the
non-default 'normalize URI' configuration options used in iRules
and/or BIG-IP LTM policies. (CVE-2017-6138)

Impact

An attacker may be able to disrupt traffic or cause the BIG-IP system
to fail over to another device in the device group. This vulnerability
affects systems with any of the following configurations :

A virtual server associated with a BIG-IPAPM profile.

A virtual server associated with an HTTP profile and a local traffic
policy that has a rule condition with the HTTP URI and Use normalized
URI options enabled (the Use normalized URI option is disabled by
default). For example, in the following configuration excerpt, the
local traffic policy is vulnerable :

ltm policy /Common/K34514540 {

requires { http } rules { vulnerable { conditions { 0 { http-uri path
normalized values { /exploitable } } } } } strategy
/Common/first-match }

A virtual server associated with an HTTP profile and an iRule using
any of the following iRules commands with the -normalized switch:
HTTP::uri

HTTP::query

HTTP::path

For example :

when HTTP_REQUEST { if { ([HTTP::uri -normalized] starts_with
'/exploitable')} { log local0.error 'K34514540 URI example' } elseif {
([HTTP::query -normalized] starts_with '/exploitable')} { log
local0.error 'K34514540 Query example' } elseif { ([HTTP::path

-normalized] starts_with '/exploitable')} { log local0.error
'K34514540 Path example' } }");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K34514540");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K34514540.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6138");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K34514540';
var vmatrix = {
  'AFM': {
    'affected': [
      '13.0.0','12.1.0-12.1.2'
    ],
    'unaffected': [
      '13.1.0','13.0.1','12.1.3'
    ],
  },
  'AM': {
    'affected': [
      '13.0.0','12.1.0-12.1.2'
    ],
    'unaffected': [
      '13.1.0','13.0.1','12.1.3'
    ],
  },
  'APM': {
    'affected': [
      '13.0.0','12.1.0-12.1.2'
    ],
    'unaffected': [
      '13.1.0','13.0.1','12.1.3'
    ],
  },
  'ASM': {
    'affected': [
      '13.0.0','12.1.0-12.1.2'
    ],
    'unaffected': [
      '13.1.0','13.0.1','12.1.3'
    ],
  },
  'AVR': {
    'affected': [
      '13.0.0','12.1.0-12.1.2'
    ],
    'unaffected': [
      '13.1.0','13.0.1','12.1.3'
    ],
  },
  'DNS': {
    'affected': [
      '13.0.0','12.1.0-12.1.2'
    ],
    'unaffected': [
      '13.1.0','13.0.1','12.1.3'
    ],
  },
  'GTM': {
    'affected': [
      '13.0.0','12.1.0-12.1.2'
    ],
    'unaffected': [
      '13.1.0','13.0.1','12.1.3'
    ],
  },
  'LTM': {
    'affected': [
      '13.0.0','12.1.0-12.1.2'
    ],
    'unaffected': [
      '13.1.0','13.0.1','12.1.3'
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
