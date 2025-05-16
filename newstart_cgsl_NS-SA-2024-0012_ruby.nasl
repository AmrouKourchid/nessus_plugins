#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0012. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193538);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2023-28756");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : ruby Vulnerability (NS-SA-2024-0012)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has ruby packages installed that are affected by a
vulnerability:

  - A ReDoS issue was discovered in the Time component through 0.2.1 in Ruby through 3.2.1. The Time parser
    mishandles invalid URLs that have specific characters. It causes an increase in execution time for parsing
    strings to Time objects. The fixed versions are 0.1.1 and 0.2.2. (CVE-2023-28756)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0012");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-28756");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ruby packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28756");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'ruby-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-debuginfo-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-devel-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-doc-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-irb-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-libs-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-tcltk-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-bigdecimal-1.2.0-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-io-console-0.4.2-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-json-1.7.7-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-minitest-4.3.2-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-psych-2.0.0-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-rake-0.9.6-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-rdoc-4.0.0-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygems-2.0.14.1-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygems-devel-2.0.14.1-36.el7.cgslv5_4.0.4.g64a5576'
  ],
  'CGSL MAIN 5.04': [
    'ruby-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-debuginfo-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-devel-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-doc-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-irb-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-libs-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'ruby-tcltk-2.0.0.648-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-bigdecimal-1.2.0-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-io-console-0.4.2-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-json-1.7.7-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-minitest-4.3.2-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-psych-2.0.0-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-rake-0.9.6-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygem-rdoc-4.0.0-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygems-2.0.14.1-36.el7.cgslv5_4.0.4.g64a5576',
    'rubygems-devel-2.0.14.1-36.el7.cgslv5_4.0.4.g64a5576'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby');
}
