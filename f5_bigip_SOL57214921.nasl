#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K57214921.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(139827);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2020-5915");
  script_xref(name:"IAVA", value:"2020-A-0395-S");

  script_name(english:"F5 Networks BIG-IP : BIG-IP TMUI XSS vulnerability (K57214921)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An undisclosed Traffic Management User Interface (TMUI),
orConfiguration utility, page contains a vulnerability which allows a
stored cross-site scripting (XSS) attack when BIG-IP systems are setup
in a device trust.

Impact

On a BIG-IP systemin a high availability (HA) configuration, users
with Resource Administrator or Administrator roles may be able store
an XSS attack, which could result in command execution by the logged
in user.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K57214921");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K57214921.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K57214921';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'AM': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'APM': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'ASM': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'AVR': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'DNS': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'GTM': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'LC': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'LTM': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'PEM': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'WAM': {
    'affected': [
      '15.0.0-15.1.0','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.4'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.4','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
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
