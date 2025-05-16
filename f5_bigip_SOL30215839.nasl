#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K30215839.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(132563);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2019-6685");

  script_name(english:"F5 Networks BIG-IP : F5 iRules vulnerability (K30215839)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 11.6.5.2 / 12.1.5.1 / 13.1.3.2 / 14.0.1.1 /
14.1.2.3 / 15.0.1.3 / 15.1.0. It is, therefore, affected by a vulnerability as referenced in the K30215839 advisory.

  - On BIG-IP versions 15.0.0-15.0.1.1, 14.1.0-14.1.2.2, 14.0.0-14.0.1, 13.1.0-13.1.3.1, 12.1.0-12.1.5, and
    11.5.2-11.6.5.1, users with access to edit iRules are able to create iRules which can lead to an elevation
    of privilege, configuration modification, and arbitrary system command execution. (CVE-2019-6685)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K30215839");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K30215839.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K30215839';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'AM': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'APM': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'ASM': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'AVR': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'DNS': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'GTM': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'LC': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'LTM': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'PEM': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
    ],
  },
  'WAM': {
    'affected': [
      '15.0.0-15.0.1','14.1.0-14.1.2','14.0.0-14.0.1','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.3','14.0.1.1','13.1.3.2','12.1.5.1','11.6.5.2'
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
