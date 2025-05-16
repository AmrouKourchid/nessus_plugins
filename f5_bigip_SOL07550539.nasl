#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K07550539.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(118624);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

  script_cve_id("CVE-2018-15311");

  script_name(english:"F5 Networks BIG-IP : TMM with LRO vulnerability (K07550539)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"When Large Receive Offload (LRO) is enabled, undisclosed traffic
patterns may cause TMM to restart. LRO has been available since 11.4.0
but is not enabled by default until13.1.0 for all platformsand 12.0.0
for Virtual Edition. (CVE-2018-15311)

Impact

An attacker may be able to disrupt traffic or cause the BIG-IP system
to fail over to another device in the device group.

Note : This vulnerability is not exposed unless Large Receive Offload
(LRO) is enabled. For more information about LRO being enabled by
default, refer toK33612400: TCP Large Receive Offload
tm.tcplargereceiveoffload database variable is enabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K07550539");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K07550539.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15311");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");

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

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K07550539';
var vmatrix = {
  'AFM': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'AM': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'APM': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'ASM': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'AVR': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'DNS': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'GTM': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'LC': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'LTM': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'PEM': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
    ],
  },
  'WAM': {
    'affected': [
      '13.0.0-13.1.0','12.1.0-12.1.3','11.6.0-11.6.3','11.5.1-11.5.6'
    ],
    'unaffected': [
      '13.1.0.6','12.1.3.6','11.6.3.3','11.5.7'
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
