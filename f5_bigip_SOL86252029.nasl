#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K86252029.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(138232);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2018-16301");

  script_name(english:"F5 Networks BIG-IP : libpcap vulnerability (K86252029)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"libpcap before 1.9.1, as used in tcpdump before 4.9.3, has a buffer
overflow and/or over-read because of errors in pcapng reading.
(CVE-2018-16301)

Impact

A local attacker may be able to corrupt data or execute arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K86252029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K86252029.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

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

var sol = 'K86252029';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'AM': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'APM': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'ASM': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'AVR': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'DNS': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'GTM': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'LC': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'LTM': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'PEM': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
    ],
  },
  'WAM': {
    'affected': [
      '15.0.0-15.1.2','14.0.0-14.1.3','13.1.0-13.1.4','12.1.0-12.1.6','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.3','14.1.3.1','13.1.4.1'
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
