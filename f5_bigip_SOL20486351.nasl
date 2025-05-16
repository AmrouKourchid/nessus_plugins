#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K20486351.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(110057);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2017-1000366");

  script_name(english:"F5 Networks BIG-IP : glibc vulnerability (K20486351)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"glibc contains a vulnerability that allows specially crafted
LD_LIBRARY_PATH values to manipulate the heap/stack, causing them to
alias, potentially resulting in arbitrary code execution. Please note
that additional hardening changes have been made to glibc to prevent
manipulation of stack and heap memory but these issues are not
directly exploitable, as such they have not been given a CVE. This
affects glibc 2.25 and earlier.(CVE-2017-1000366)

Impact

This vulnerability allows unauthorized disclosure of information,
unauthorized modification, and disruption of service.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K20486351");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K20486351.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000366");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");

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

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K20486351';
var vmatrix = {
  'AFM': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'AM': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'APM': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'ASM': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'AVR': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'DNS': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'GTM': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'LC': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'LTM': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'PEM': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  },
  'WAM': {
    'affected': [
      '12.0.0-12.1.3','11.4.0-11.6.3','11.2.1'
    ],
    'unaffected': [
      '12.1.3.2'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
