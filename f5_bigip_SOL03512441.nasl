#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K03512441.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(135013);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/20");

  script_cve_id("CVE-2019-13136");

  script_name(english:"F5 Networks BIG-IP : ImageMagick vulnerability (K03512441)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"ImageMagick before 7.0.8-50 has an integer overflow vulnerability in
the function TIFFSeekCustomStream in coders/tiff.c. (CVE-2019-13136)

Impact

BIG-IP (AAM,Edge Gateway, WebAccelerator)

This issue affects BIG-IP systems only when WAM or AAM is
provisioned.If exploited, this vulnerability may result in partial
violation of BIG-IP integrity andloss of informationand access.

BIG-IP (LTM, AFM, Analytics, APM, ASM, DNS, FPS, GTM, Link Controller,
PEM),BIG-IQ Centralized Management,Enterprise Manager, F5
iWorkflow,Traffix SDC

There is no impact; these F5 products are not affected by this
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K03512441");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K03512441.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13136");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K03512441';
var vmatrix = {
  'AM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0.2','15.0.1.3','14.1.2.5','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'WAM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.0.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.5.2-11.6.5'
    ],
    'unaffected': [
      '15.1.0.2','15.0.1.3','14.1.2.5','13.1.3.4','12.1.5.2','11.6.5.2'
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
