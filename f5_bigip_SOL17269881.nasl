#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K17269881.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(138230);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2018-12207");

  script_name(english:"F5 Networks BIG-IP : Intel MCE vulnerability (K17269881)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Improper invalidation for page table updates by a virtual guest
operating system for multiple Intel(R) Processors may allow an
authenticated user to potentially enable denial of service of the host
system via local access. (CVE-2018-12207)

Impact

A privileged guest user may use this flaw to induce a hardware Machine
Check Error (MCE) that halts the host processor and resultsin a
denial-of-service (DoS) scenario.

This is a hardware issue and requires kernel updates to remediate.
This issue impacts all BIG-IP platforms using the following Intel
processor families :

Xeon

Pentium Gold

Core X-series

Core i

Celeron G

The following BIG-IP platforms are vulnerable :

BIG-IP 2000s, 2200s, 4000s, 4200v, 5000s, 5050s, 5200v,5250v, 5250v
fips, 7000s, 7200v , 7200v FIPS , 7250v series

BIG-IP 10000s, 10050s, 10055s, 10150s NEBS, 10200v, 10200v FIPS,
10200v SSL, 10250v, 10255v, 10350v, 10350v NEBS, 11050 NEBS,
12250vseries

BIG-IP iSeries platforms:i850, i2x00,i4x00, i5x00, i5820-DF, i7x00,
i7x00-D2, i7820-DF, i10x00 / i10x00-D2, i11x00, i11x00-DS, i15x00

VIPRION B2100, VIPRION B2150 , VIPRION B2250, VIPRION B4300 , VIPRION
B4340N

Enterprise Manager 4000

BIG-IQ 7000

The following BIG-IP platforms are not vulnerable :

BIG-IP 800, 1600, 3600, 3900, 4200, 4340, 6900 series

BIG-IP 8900, 8950, 1100, 11050, 11050 FIPS series");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K17269881");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K17269881.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
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

var sol = 'K17269881';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
    ],
  },
  'AM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
    ],
  },
  'APM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
    ],
  },
  'ASM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
    ],
  },
  'AVR': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
    ],
  },
  'DNS': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
    ],
  },
  'GTM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
    ],
  },
  'LC': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
    ],
  },
  'LTM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
    ],
  },
  'PEM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.5','15.0.1.4','14.1.2.8','13.1.3.5'
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
