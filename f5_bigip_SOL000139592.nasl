#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000139592.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(197039);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2023-29469");

  script_name(english:"F5 Networks BIG-IP : libxml2 vulnerability (K000139592)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K000139592 advisory.

    An issue was discovered in libxml2 before 2.10.4. When hashing empty dict strings in a crafted XML
    document, xmlDictComputeFastKey in dict.c can produce non-deterministic values, leading to various logic
    and memory errors, such as a double free. This behavior occurs because there is an attempt to use the
    first byte of an empty string, and any value is possible (not solely the '\0' value).(CVE-2023-29469)

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000139592");
  script_set_attribute(attribute:"solution", value:
"The vendor has acknowledged the vulnerability, but no solution has been provided.
Refer to the vendor for remediation guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29469");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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


var sol = 'K000139592';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
  },
  'AM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
  },
  'AVR': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
  },
  'DNS': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
  },
  'LC': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
  },
  'LTM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.5','15.1.0-15.1.10'
    ],
  },
  'PEM': {
    'affected': [
      '17.1.0-17.5.0','16.1.0-16.1.5','15.1.0-15.1.10'
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
