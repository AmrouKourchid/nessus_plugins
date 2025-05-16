#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K44885536.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(126403);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2019-6622");

  script_name(english:"F5 Networks BIG-IP : iControl REST vulnerability (K44885536)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Undisclosed iControl REST worker is vulnerable to command injection by
an administrator or resource administrator user. This attack is only
exploitable on multi-bladed systems.

Thevulnerability allows bypass of Appliance mode security on BIG-IP
systems by allowing the execution of arbitrary Advanced Shell (bash)
commands. Insystems without Appliance mode security,the administrator
andresource administrator users will likely have this level of access
already. F5 considers this a security concern mostly for systems
deployed in Appliance mode, but it's also a valid attack vector for
users that do not already have bash access granted. For example, a
resource administrator whodoes not already have bash access explicitly
granted in the user configuration can be exploited as an attack
vector. (CVE-2019-6622)

Impact

A remote attacker can exploit the vulnerability byexecutingarbitrary
bash commands on a vulnerable multi-bladed system.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K44885536");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K44885536.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/02");

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

var sol = 'K44885536';
var vmatrix = {
  'AFM': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'AM': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'APM': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'ASM': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'AVR': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'DNS': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'GTM': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'LC': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'LTM': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'PEM': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
    ],
  },
  'WAM': {
    'affected': [
      '14.0.0-14.1.0.5','13.0.0-13.1.1.4','12.1.0-12.1.5','11.5.1-11.6.5'
    ],
    'unaffected': [
      '15.0.0','14.1.0.6','14.0.1.1','13.1.1.5','12.1.5.1'
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
