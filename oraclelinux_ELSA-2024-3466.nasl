#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-3466.
##

include('compat.inc');

if (description)
{
  script_id(198276);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2023-6597", "CVE-2024-0450", "CVE-2024-3651");

  script_name(english:"Oracle Linux 8 : python39:3.9 / and / python39-devel:3.9 (ELSA-2024-3466)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-3466 advisory.

    - Security fixes for CVE-2023-6597 and CVE-2024-0450

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-3466.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3651");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8:10:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8:9:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python39-wheel-wheel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var appstreams = {
    'python39-devel:3.9': [
      {'reference':'python39-debug-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-debug-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ],
    'python39:3.9': [
      {'reference':'python39-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-PyMySQL-0.10.1-2.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-chardet-3.0.4-19.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-3.0.1.module+el8.10.0+90269+2fa22b99', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-devel-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idle-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idna-2.10-4.module+el8.10.0+90341+71ca88f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-libs-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-7.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-doc-1.19.4-3.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-20.2.4-9.module+el8.10.0+90269+2fa22b99', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-wheel-20.2.4-9.module+el8.10.0+90269+2fa22b99', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-ply-3.11-10.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-3.module+el8.10.0+90269+2fa22b99', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-3.module+el8.10.0+90269+2fa22b99', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-3.module+el8.10.0+90269+2fa22b99', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pycparser-2.20-3.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pysocks-1.7.1-4.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-requests-2.25.0-3.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-rpm-macros-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-5.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-50.3.2-5.module+el8.10.0+90269+2fa22b99', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-wheel-50.3.2-5.module+el8.10.0+90269+2fa22b99', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-six-1.15.0-3.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-test-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-tkinter-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-toml-0.10.1-5.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-urllib3-1.25.10-5.module+el8.10.0+90269+2fa22b99', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wheel-0.35.1-4.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-wheel-0.35.1-4.module+el8.9.0+90016+9c2d6573', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-PyMySQL-0.10.1-2.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-chardet-3.0.4-19.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-3.0.1.module+el8.10.0+90269+2fa22b99', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-devel-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idle-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-idna-2.10-4.module+el8.10.0+90341+71ca88f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-libs-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-7.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-doc-1.19.4-3.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-20.2.4-9.module+el8.10.0+90269+2fa22b99', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-wheel-20.2.4-9.module+el8.10.0+90269+2fa22b99', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-ply-3.11-10.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-3.module+el8.10.0+90269+2fa22b99', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-3.module+el8.10.0+90269+2fa22b99', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-3.module+el8.10.0+90269+2fa22b99', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pycparser-2.20-3.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pysocks-1.7.1-4.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-requests-2.25.0-3.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-rpm-macros-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-5.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-50.3.2-5.module+el8.10.0+90269+2fa22b99', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-wheel-50.3.2-5.module+el8.10.0+90269+2fa22b99', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-six-1.15.0-3.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-test-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-tkinter-3.9.19-1.module+el8.10.0+90341+71ca88f4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-toml-0.10.1-5.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-urllib3-1.25.10-5.module+el8.10.0+90269+2fa22b99', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wheel-0.35.1-4.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-wheel-0.35.1-4.module+el8.9.0+90016+9c2d6573', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39-devel:3.9 / python39:3.9');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python39 / python39-PyMySQL / python39-cffi / etc');
}
