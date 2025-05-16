#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K24401914.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(124419);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2019-6612");

  script_name(english:"F5 Networks BIG-IP : DNS vulnerability (K24401914)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"On BIG-IP 14.0.0-14.1.0.1, 13.0.0-13.1.1.4, 12.1.0-12.1.4,
11.6.1-11.6.3.4, and 11.5.2-11.5.8, DNS query TCP connections that are
aborted before receiving a response from a DNS cache may cause TMM to
restart. (CVE-2019-6612)

Impact

A BIG-IP virtual server associated with a TCP and DNS profile that has
DNS Cache enabled will be affected by this vulnerability. The affected
BIG-IP system temporarily fails to process traffic as it recovers from
a Traffic Management Microkernel (TMM) restart, and devices configured
in a device group may fail over.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K24401914");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K24401914.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
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

var sol = 'K24401914';
var vmatrix = {
  'AFM': {
    'affected': [
      '14.0.0-14.1.0','13.0.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.3','11.5.1-11.5.8'
    ],
    'unaffected': [
      '15.0.0','14.1.0.2','13.1.1.5','12.1.4.1','11.6.4','11.5.9'
    ],
  },
  'AM': {
    'affected': [
      '14.0.0-14.1.0','13.0.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.3','11.5.1-11.5.8'
    ],
    'unaffected': [
      '15.0.0','14.1.0.2','13.1.1.5','12.1.4.1','11.6.4','11.5.9'
    ],
  },
  'APM': {
    'affected': [
      '14.0.0-14.1.0','13.0.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.3','11.5.1-11.5.8'
    ],
    'unaffected': [
      '15.0.0','14.1.0.2','13.1.1.5','12.1.4.1','11.6.4','11.5.9'
    ],
  },
  'ASM': {
    'affected': [
      '14.0.0-14.1.0','13.0.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.3','11.5.1-11.5.8'
    ],
    'unaffected': [
      '15.0.0','14.1.0.2','13.1.1.5','12.1.4.1','11.6.4','11.5.9'
    ],
  },
  'DNS': {
    'affected': [
      '14.0.0-14.1.0','13.0.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.3','11.5.1-11.5.8'
    ],
    'unaffected': [
      '15.0.0','14.1.0.2','13.1.1.5','12.1.4.1','11.6.4','11.5.9'
    ],
  },
  'GTM': {
    'affected': [
      '14.0.0-14.1.0','13.0.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.3','11.5.1-11.5.8'
    ],
    'unaffected': [
      '15.0.0','14.1.0.2','13.1.1.5','12.1.4.1','11.6.4','11.5.9'
    ],
  },
  'LC': {
    'affected': [
      '14.0.0-14.1.0','13.0.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.3','11.5.1-11.5.8'
    ],
    'unaffected': [
      '15.0.0','14.1.0.2','13.1.1.5','12.1.4.1','11.6.4','11.5.9'
    ],
  },
  'LTM': {
    'affected': [
      '14.0.0-14.1.0','13.0.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.3','11.5.1-11.5.8'
    ],
    'unaffected': [
      '15.0.0','14.1.0.2','13.1.1.5','12.1.4.1','11.6.4','11.5.9'
    ],
  },
  'PEM': {
    'affected': [
      '14.0.0-14.1.0','13.0.0-13.1.1','12.1.0-12.1.4','11.6.1-11.6.3','11.5.1-11.5.8'
    ],
    'unaffected': [
      '15.0.0','14.1.0.2','13.1.1.5','12.1.4.1','11.6.4','11.5.9'
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
