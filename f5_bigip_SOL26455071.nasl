#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K26455071.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(123031);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id("CVE-2019-6604");

  script_name(english:"F5 Networks BIG-IP : BIG-IP HSB vulnerability (K26455071)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Under certain conditions, hardware systems with a High-Speed Bridge
(HSB) using non-default Layer 2 forwarding configurations may
experience a lockup of the HSB. (CVE-2019-6604)

This vulnerability occurs when all of the following conditions are 
met :

A VLAN group is configured.

The vlangroup.flow.allocate database key is disabled. Note : This is
not the default configuration.

You are running the BIG-IP system or BIG-IP Virtual Clustered
Multiprocessing (vCMP) guests on one of the following hardware
platforms: BIG-IP i850 (C117)

BIG-IP i2x00 (C117)

BIG-IP 3900 (C106)

BIG-IP i4x00 (C115)

BIG-IP 5000 (C109)

BIG-IP i5x00 (C119)

BIG-IP i5820-DF (C125)

BIG-IP 6900 (D104)

BIG-IP 7000 (D110)

BIG-IP 8900 (D106)

BIG-IP i7x00 (C118)

BIG-IP i7820-DF (C126)

BIG-IP 8950 (D107)

BIG-IP 10000/102x0/ (D113)

BIG-IP 10350 (D112)

BIG-IP i10x00 (C116)

BIG-IP 11000 (E101)

BIG-IP 11050 (E102)

BIG-IP i11x00 (C123)

BIG-IP i11800-DS (C124)

BIG-IP 12250 (D111)

BIG-IP i15x00 (D116)

VIPRION 2400 (B2100, B2150, B2250)

VIPRION (B4100, B4200, B4300, B4340, B4450)

Note : BIG-IP Virtual Edition (VE) and Cloud Edition products are not
affected.

Impact

The BIG-IP system stops processing traffic, eventually leading to a
failover to another host in the high availability (HA) group.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K26455071");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K26455071.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6604");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/25");

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

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K26455071';
var vmatrix = {
  'AFM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'AM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'APM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'ASM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'AVR': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'DNS': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'GTM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'LC': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'LTM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'PEM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
    ],
  },
  'WAM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.0-12.1.3','11.6.0-11.6.3','11.2.1-11.5.8'
    ],
    'unaffected': [
      '14.1.0','14.0.0.3','13.1.1.2','12.1.3.7','11.6.4','11.5.9'
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
