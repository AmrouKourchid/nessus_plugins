#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K25595031.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(144344);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2020-27725");
  script_xref(name:"IAVA", value:"2021-A-0004-S");

  script_name(english:"F5 Networks BIG-IP : zxfrd vulnerability (K25595031)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"zxfrd leaks memory when listing DNS zones. Zones can be listed via
TMSH, iControl or SNMP; only users with access to those services can
trigger this vulnerability.(CVE-2020-27725)

Impact

The memory leak by the zxfrd processeventually causesthe system to
experiencean out-of-memory condition. As a result, systems in a high
availability (HA) configurationmayexperience a failover. This
vulnerability affects only BIG-IP systems that are provisioned with
BIG-IP DNS or BIG-IP GTM andat least one DNS zone.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K25595031");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K25595031.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var sol = 'K25595031';
var vmatrix = {
  'DNS': {
    'affected': [
      '15.0.0-15.1.0','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.1','14.1.3.1','13.1.3.5','12.1.5.3','11.6.5.3'
    ],
  },
  'GTM': {
    'affected': [
      '15.0.0-15.1.0','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.1','14.1.3.1','13.1.3.5','12.1.5.3','11.6.5.3'
    ],
  },
  'LC': {
    'affected': [
      '15.0.0-15.1.0','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.1','14.1.3.1','13.1.3.5','12.1.5.3','11.6.5.3'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
