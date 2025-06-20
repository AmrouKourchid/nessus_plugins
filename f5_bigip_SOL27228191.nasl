#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K27228191.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(129307);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2018-7159");

  script_name(english:"F5 Networks BIG-IP : Node.js vulnerability (K27228191)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The HTTP parser in all current versions of Node.js ignores spaces in
the `Content-Length` header, allowing input such as `Content-Length: 1
2` to be interpreted as having a value of `12`. The HTTP specification
does not allow for spaces in the `Content-Length` value and the
Node.js HTTP parser has been brought into line on this particular
difference. The security risk of this flaw to Node.js users is
considered to be VERY LOW as it is difficult, and may be impossible,
to craft an attack that makes use of this flaw in a way that could not
already be achieved by supplying an incorrect value for
`Content-Length`. Vulnerabilities may exist in user-code that make
incorrect assumptions about the potential accuracy of this value
compared to the actual length of the data supplied. Node.js users
crafting lower-level HTTP utilities are advised to re-check the length
of any input supplied after parsing is complete. (CVE-2018-7159)

Impact

BIG-IP

According to CVE-2018-7159, it may be impossible to craft an attack
that uses this flaw in a way that could not already be achieved by
supplying an incorrect 'Content-Length' value. However, when the flaw
is exploited, it may cause the affected Node.js component to behave
unexpectedly.

BIG-IQ, F5 iWorkflow, Enterprise Manager, and Traffix SDC

There is no impact; these F5 products are not affected by this
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K27228191");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K27228191.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7159");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/25");

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

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K27228191';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'AM': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'APM': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'ASM': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'AVR': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'DNS': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'GTM': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'LC': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'LTM': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'PEM': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
    ],
  },
  'WAM': {
    'affected': [
      '15.0.0-15.0.1','14.0.0-14.1.2','13.0.0-13.1.3','12.1.0-12.1.5','11.2.1-11.6.5'
    ],
    'unaffected': [
      '15.1.0','15.0.1.3','14.1.2.1','13.1.3.4'
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
