#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K62532311.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(125483);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2012-6708");

  script_name(english:"F5 Networks BIG-IP : jQuery vulnerability (K62532311)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"jQuery before 1.9.0 is vulnerable to Cross-site Scripting (XSS)
attacks. The jQuery(strInput) function does not differentiate
selectors from HTML in a reliable fashion. In vulnerable versions,
jQuery determined whether the input was HTML by looking for the '<'
character anywhere in the string, giving attackers more flexibility
when attempting to construct a malicious payload. In fixed versions,
jQuery only deems the input to be HTML if it explicitly starts with
the '<' character, limiting exploitability only to attackers who can
control the beginning of a string, which is far less common.
(CVE-2012-6708)

Impact

This vulnerability allows an authenticated user to perform an
unauthorized modification.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K62532311");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K62532311.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-6708");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/29");

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

var sol = 'K62532311';
var vmatrix = {
  'AFM': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'AM': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'APM': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'ASM': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'AVR': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'DNS': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'GTM': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'LC': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'LTM': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'PEM': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
    ],
  },
  'WAM': {
    'affected': [
      '14.1.0-14.1.2','14.0.0-14.0.1','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.2.3','13.1.3.2','12.1.5.2'
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
