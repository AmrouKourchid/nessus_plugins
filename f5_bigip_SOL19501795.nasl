#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K19501795.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(126397);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/13");

  script_cve_id("CVE-2019-6631");

  script_name(english:"F5 Networks BIG-IP : BIG-IP HTTP profile vulnerability (K19501795)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"iRules performing HTTP header manipulation may cause an interruption
to service when processing traffic handled by a Virtual Server with an
associated HTTP profile, in specific circumstances, when the requests
do not strictly conform to RFCs. (CVE-2019-6631)

Impact

The BIG-IP system Traffic Management Microkernel (TMM) process may
produce a core file and fail over to another system in the high
availability (HA) group.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K19501795");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K19501795.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6631");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
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

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K19501795';
var vmatrix = {
  'AFM': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'AM': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'APM': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'ASM': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'AVR': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'DNS': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'GTM': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'LC': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'LTM': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'PEM': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
    ],
  },
  'WAM': {
    'affected': [
      '11.5.2-11.6.5'
    ],
    'unaffected': [
      '12.0.0','11.6.5.1'
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
