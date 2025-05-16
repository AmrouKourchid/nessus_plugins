#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K05122252.
#
# The text description of this plugin is (C) F5 Networks.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159629);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2012-6711");

  script_name(english:"F5 Networks BIG-IP : Bash vulnerability (K05122252)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A heap-based buffer overflow exists in GNU Bash before 4.3 when wide
characters, not supported by the current locale set in the LC_CTYPE
environment variable, are printed through the echo built-in function.
A local attacker, who can provide data to print through the 'echo -e'
built-in function, may use this flaw to crash a script or execute code
with the privileges of the bash process. This occurs because
ansicstr() in lib/sh/strtrans.c mishandles u32cconv(). (CVE-2012-6711)

Impact

A local attacker can perform a buffer-overflow attack, which can lead
to data corruption, allow the malicious code to be run, or cause the
program to terminate.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K05122252");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K05122252.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-6711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/11");

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

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K05122252';
var vmatrix = {
  'AFM': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'AM': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'APM': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'ASM': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'AVR': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'DNS': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'GTM': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'LC': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'LTM': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'PEM': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
    ],
  },
  'WAM': {
    'affected': [
      '16.0.0-16.1.2','15.0.0-15.1.5','14.1.0-14.1.4'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6'
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
