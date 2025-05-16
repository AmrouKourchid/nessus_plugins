#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K44200194.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(184244);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id("CVE-2018-5501");

  script_name(english:"F5 Networks BIG-IP : DNS TCP virtual server vulnerability (K44200194)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 11.6.5.3 / 12.1.3.2 / 13.1.0. It is,
therefore, affected by a vulnerability as referenced in the K44200194 advisory.

  - In some circumstances, on F5 BIG-IP systems running 13.0.0, 12.1.0 - 12.1.3.1, any 11.6.x or 11.5.x
    release, or 11.2.1, TCP DNS profile allows excessive buffering due to lack of flow control.
    (CVE-2018-5501)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K44200194");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K44200194.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5501");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K44200194';
var vmatrix = {
  'AFM': {
    'affected': [
      '13.0.0','12.1.0-12.1.3','11.6.1-11.6.5','11.5.1-11.5.0','11.2.1'
    ],
    'unaffected': [
      '13.1.0','12.1.3.2','11.6.5.3'
    ],
  },
  'AM': {
    'affected': [
      '13.0.0','12.1.0-12.1.3','11.6.1-11.6.5','11.5.1-11.5.0','11.2.1'
    ],
    'unaffected': [
      '13.1.0','12.1.3.2','11.6.5.3'
    ],
  },
  'APM': {
    'affected': [
      '13.0.0','12.1.0-12.1.3','11.6.1-11.6.5','11.5.1-11.5.0','11.2.1'
    ],
    'unaffected': [
      '13.1.0','12.1.3.2','11.6.5.3'
    ],
  },
  'ASM': {
    'affected': [
      '13.0.0','12.1.0-12.1.3','11.6.1-11.6.5','11.5.1-11.5.0','11.2.1'
    ],
    'unaffected': [
      '13.1.0','12.1.3.2','11.6.5.3'
    ],
  },
  'AVR': {
    'affected': [
      '13.0.0','12.1.0-12.1.3','11.6.1-11.6.5','11.5.1-11.5.0','11.2.1'
    ],
    'unaffected': [
      '13.1.0','12.1.3.2','11.6.5.3'
    ],
  },
  'DNS': {
    'affected': [
      '13.0.0','12.1.0-12.1.3','11.6.1-11.6.5','11.5.1-11.5.0','11.2.1'
    ],
    'unaffected': [
      '13.1.0','12.1.3.2','11.6.5.3'
    ],
  },
  'GTM': {
    'affected': [
      '13.0.0','12.1.0-12.1.3','11.6.1-11.6.5','11.5.1-11.5.0','11.2.1'
    ],
    'unaffected': [
      '13.1.0','12.1.3.2','11.6.5.3'
    ],
  },
  'LTM': {
    'affected': [
      '13.0.0','12.1.0-12.1.3','11.6.1-11.6.5','11.5.1-11.5.0','11.2.1'
    ],
    'unaffected': [
      '13.1.0','12.1.3.2','11.6.5.3'
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
