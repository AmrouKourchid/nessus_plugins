#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-a03b06dbd0
#

include('compat.inc');

if (description)
{
  script_id(211244);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id(
    "CVE-2024-4577",
    "CVE-2024-8925",
    "CVE-2024-8926",
    "CVE-2024-8927",
    "CVE-2024-9026"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/03");
  script_xref(name:"IAVA", value:"2024-A-0330-S");
  script_xref(name:"FEDORA", value:"2024-a03b06dbd0");
  script_xref(name:"IAVA", value:"2024-A-0609-S");

  script_name(english:"Fedora 41 : php (2024-a03b06dbd0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 41 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-a03b06dbd0 advisory.

    **PHP version 8.3.12** (26 Sep 2024)

    **CGI:**

    * Fixed bug [GHSA-p99j-rfp4-xqvq](https://github.com/php/php-src/security/advisories/GHSA-p99j-rfp4-xqvq)
    (Bypass of CVE-2024-4577, Parameter Injection Vulnerability). (**CVE-2024-8926**) (nielsdos)
    * Fixed bug [GHSA-94p6-54jq-9mwp](https://github.com/php/php-src/security/advisories/GHSA-94p6-54jq-9mwp)
    (cgi.force_redirect configuration is bypassable due to the environment variable collision).
    (**CVE-2024-8927**) (nielsdos)

    **Core:**

    * Fixed bug [GH-15408](https://github.com/php/php-src/issues/15408) (MSan false-positve on
    zend_max_execution_timer). (zeriyoshi)
    * Fixed bug [GH-15515](https://github.com/php/php-src/issues/15515) (Configure error grep illegal option
    q). (Peter Kokot)
    * Fixed bug [GH-15514](https://github.com/php/php-src/issues/15514) (Configure error: genif.sh: syntax
    error). (Peter Kokot)
    * Fixed bug [GH-15565](https://github.com/php/php-src/issues/15565) (--disable-ipv6 during compilation
    produces error EAI_SYSTEM not found). (nielsdos)
    * Fixed bug [GH-15587](https://github.com/php/php-src/issues/15587) (CRC32 API build error on arm 32-bit).
    (Bernd Kuhls, Thomas Petazzoni)
    * Fixed bug [GH-15330](https://github.com/php/php-src/issues/15330) (Do not scan generator frames more
    than once). (Arnaud)
    * Fixed uninitialized lineno in constant AST of internal enums. (ilutov)

    **Curl:**

    * FIxed bug [GH-15547](https://github.com/php/php-src/issues/15547) (curl_multi_select overflow on timeout
    argument). (David Carlier)

    **DOM:**

    * Fixed bug [GH-15551](https://github.com/php/php-src/issues/15551) (Segmentation fault (access null
    pointer) in ext/dom/xml_common.h). (nielsdos)
    * Fixed bug [GH-15654](https://github.com/php/php-src/issues/15654) (Signed integer overflow in
    ext/dom/nodelist.c). (nielsdos)

    **Fileinfo:**

    * Fixed bug [GH-15752](https://github.com/php/php-src/issues/15752) (Incorrect error message for
    finfo_file with an empty filename argument). (DanielEScherzer)

    **FPM:**

    * Fixed bug [GHSA-865w-9rf3-2wh5](https://github.com/php/php-src/security/advisories/GHSA-865w-9rf3-2wh5)
    (Logs from childrens may be altered). (**CVE-2024-9026**) (Jakub Zelenka)

    **MySQLnd:**

    * Fixed bug [GH-15432](https://github.com/php/php-src/issues/15432) (Heap corruption when querying a
    vector). (cmb, Kamil Tekiela)

    **Opcache:**

    * Fixed bug [GH-15661](https://github.com/php/php-src/issues/15661) (Access null pointer in
    Zend/Optimizer/zend_inference.c). (nielsdos)
    * Fixed bug [GH-15658](https://github.com/php/php-src/issues/15658) (Segmentation fault in
    Zend/zend_vm_execute.h). (nielsdos)

    **SAPI:**

    * Fixed bug [GHSA-9pqp-7h25-4f32](https://github.com/php/php-src/security/advisories/GHSA-9pqp-7h25-4f32)
    (Erroneous parsing of multipart form data). (**CVE-2024-8925**) (Arnaud)

    **Standard:**

    * Fixed bug [GH-15552](https://github.com/php/php-src/issues/15552) (Signed integer overflow in
    ext/standard/scanf.c). (cmb)

    **Streams:**

    * Fixed bug [GH-15628](https://github.com/php/php-src/issues/15628) (php_stream_memory_get_buffer() not
    zero-terminated). (cmb)

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-a03b06dbd0");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4577");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^41([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 41', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-8.3.12-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php');
}
