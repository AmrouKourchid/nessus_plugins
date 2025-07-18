#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K58494243.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(136141);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2020-5891");

  script_name(english:"F5 Networks BIG-IP : BIG-IP HTTP/2 vulnerability (K58494243)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Undisclosed HTTP/2 requests can lead to a denial of service when sent
to a virtual server configured with the Fallback Host setting and a
server-side HTTP/2 profile. (CVE-2020-5891)

Impact

The Traffic Management Microkernel (TMM) may generate a core file and
restart, causing a traffic disruption or failover event. This
vulnerability affects only virtual servers with the Fallback Host
setting configured and a server-side HTTP/2 profile assigned.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K58494243");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K58494243.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5891");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
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

var sol = 'K58494243';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.0.0','15.1.0.2','15.0.1.3','14.1.2.5'
    ],
  },
  'AM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.0.0','15.1.0.2','15.0.1.3','14.1.2.5'
    ],
  },
  'APM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.0.0','15.1.0.2','15.0.1.3','14.1.2.5'
    ],
  },
  'ASM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.0.0','15.1.0.2','15.0.1.3','14.1.2.5'
    ],
  },
  'AVR': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.0.0','15.1.0.2','15.0.1.3','14.1.2.5'
    ],
  },
  'LC': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.0.0','15.1.0.2','15.0.1.3','14.1.2.5'
    ],
  },
  'LTM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.0.0','15.1.0.2','15.0.1.3','14.1.2.5'
    ],
  },
  'PEM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.0.0','15.1.0.2','15.0.1.3','14.1.2.5'
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
