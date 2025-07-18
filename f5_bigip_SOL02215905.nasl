#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K02215905.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(184216);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/07");

  script_cve_id("CVE-2018-16056", "CVE-2018-16057", "CVE-2018-16058");

  script_name(english:"F5 Networks BIG-IP : Wireshark vulnerabilities (K02215905)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the K02215905 advisory.

  - In Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0 to 2.2.16, the Bluetooth Attribute Protocol
    dissector could crash. This was addressed in epan/dissectors/packet-btatt.c by verifying that a dissector
    for a specific UUID exists. (CVE-2018-16056)

  - In Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0 to 2.2.16, the Radiotap dissector could crash. This
    was addressed in epan/dissectors/packet-ieee80211-radiotap-iter.c by validating iterator operations.
    (CVE-2018-16057)

  - In Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0 to 2.2.16, the Bluetooth AVDTP dissector could
    crash. This was addressed in epan/dissectors/packet-btavdtp.c by properly initializing a data structure.
    (CVE-2018-16058)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K02215905");
  script_set_attribute(attribute:"solution", value:
"The vendor has acknowledged the vulnerability, but no solution has been provided.
Refer to the vendor for remediation guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/02");

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

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K02215905';
var vmatrix = {
  'AFM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'AM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'APM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'ASM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'AVR': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'DNS': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'GTM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'LC': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'LTM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'PEM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
    ],
  },
  'WAM': {
    'affected': [
      '14.0.0','13.0.0-13.1.1','12.1.3'
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
