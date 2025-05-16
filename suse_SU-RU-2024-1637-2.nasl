#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-SUSE-RU-2024:1637-2. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(200803);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/21");

  script_cve_id("CVE-2023-30608");
  script_xref(name:"SuSE", value:"SUSE-RU-2024:1637-2");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 : Recommended update for google-cloud SDK (SUSE-SU-SUSE-RU-2024:1637-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by a vulnerability as referenced in the SUSE-SU-SUSE-RU-2024:1637-2 advisory.

    - Add python311 cloud services packages and dependencies (jsc#PED-7987, jsc#PED-6697)
    - Bellow 5 binaries Obsolete the python3.6 counterpart:
        python311-google-resumable-media
        python311-google-api-core
        python311-google-cloud-storage
        python311-google-cloud-core
        python311-googleapis-common-protos

    - Regular python311 updates (without Obsoletes):
        python-google-auth
        python-grpcio
        python-sqlparse

    - New python311 packages:
        libcrc32c
        python-google-cloud-appengine-logging
        python-google-cloud-artifact-registry
        python-google-cloud-audit-log
        python-google-cloud-build
        python-google-cloud-compute
        python-google-cloud-dns
        python-google-cloud-domains
        python-google-cloud-iam
        python-google-cloud-kms-inventory
        python-google-cloud-kms
        python-google-cloud-logging
        python-google-cloud-run
        python-google-cloud-secret-manager
        python-google-cloud-service-directory
        python-google-cloud-spanner
        python-google-cloud-vpc-access
        python-google-crc32c
        python-grpc-google-iam-v1
        python-grpcio-status
        python-proto-plus

    In python-sqlparse this security issue was fixed:

    CVE-2023-30608: Fixed parser that contained a regular expression that is vulnerable to ReDOS (Regular
    Expression Denial of Service) (bsc#1210617)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210617");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035667.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30608");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcrc32c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcrc32c1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-apipkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-cachetools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-certifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-charset-normalizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-api-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-auth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-appengine-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-artifact-registry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-audit-log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-domains");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-iam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-kms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-kms-inventory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-run");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-secret-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-service-directory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-spanner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-cloud-vpc-access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-crc32c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-google-resumable-media");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-googleapis-common-protos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-grpc-google-iam-v1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-grpcio-status");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-iniconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-proto-plus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pyOpenSSL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pyasn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pyasn1-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-urllib3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libcrc32c-devel-1.1.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libcrc32c1-1.1.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-apipkg-3.0.1-150400.12.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-apipkg-3.0.1-150400.12.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-cachetools-5.3.1-150400.8.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-cachetools-5.3.1-150400.8.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-certifi-2023.7.22-150400.12.6.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-certifi-2023.7.22-150400.12.6.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-cffi-1.15.1-150400.8.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-cffi-1.15.1-150400.8.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-charset-normalizer-3.1.0-150400.9.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-charset-normalizer-3.1.0-150400.9.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-api-core-2.15.0-150400.5.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-auth-2.27.0-150400.6.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-auth-2.27.0-150400.6.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-appengine-logging-1.4.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-artifact-registry-1.11.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-audit-log-0.2.5-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-build-3.22.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-compute-1.15.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-core-2.4.1-150400.5.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-dns-0.35.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-domains-1.7.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-iam-2.13.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-kms-2.21.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-kms-inventory-0.2.2-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-logging-3.9.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-run-0.10.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-secret-manager-2.17.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-service-directory-1.11.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-spanner-3.40.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-storage-2.14.0-150400.10.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-cloud-vpc-access-1.10.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-crc32c-1.5.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-google-resumable-media-2.7.0-150400.10.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-googleapis-common-protos-1.62.0-150400.10.4.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-grpc-google-iam-v1-0.13.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-grpcio-status-1.60.1-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-idna-3.4-150400.11.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-idna-3.4-150400.11.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-iniconfig-2.0.0-150400.10.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-iniconfig-2.0.0-150400.10.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-proto-plus-1.23.0-150400.9.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-py-1.11.0-150400.12.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-py-1.11.0-150400.12.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pyOpenSSL-23.2.0-150400.3.10.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pyOpenSSL-23.2.0-150400.3.10.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pyasn1-0.5.0-150400.12.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pyasn1-0.5.0-150400.12.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pyasn1-modules-0.3.0-150400.12.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pyasn1-modules-0.3.0-150400.12.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pycparser-2.21-150400.12.7.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pycparser-2.21-150400.12.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pytz-2023.3-150400.6.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-pytz-2023.3-150400.6.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-requests-2.31.0-150400.6.8.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-requests-2.31.0-150400.6.8.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-rsa-4.9-150400.12.7.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-rsa-4.9-150400.12.7.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-setuptools-67.7.2-150400.3.12.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-setuptools-67.7.2-150400.3.12.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-sqlparse-0.4.4-150400.6.4.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-urllib3-2.0.7-150400.7.14.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'python311-urllib3-2.0.7-150400.7.14.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libcrc32c-devel-1.1.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'libcrc32c1-1.1.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-apipkg-3.0.1-150400.12.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-apipkg-3.0.1-150400.12.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-cachetools-5.3.1-150400.8.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-cachetools-5.3.1-150400.8.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-certifi-2023.7.22-150400.12.6.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-certifi-2023.7.22-150400.12.6.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-cffi-1.15.1-150400.8.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-cffi-1.15.1-150400.8.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-charset-normalizer-3.1.0-150400.9.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-charset-normalizer-3.1.0-150400.9.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-api-core-2.15.0-150400.5.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-auth-2.27.0-150400.6.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-auth-2.27.0-150400.6.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-appengine-logging-1.4.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-artifact-registry-1.11.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-audit-log-0.2.5-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-build-3.22.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-compute-1.15.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-core-2.4.1-150400.5.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-dns-0.35.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-domains-1.7.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-iam-2.13.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-kms-2.21.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-kms-inventory-0.2.2-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-logging-3.9.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-run-0.10.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-secret-manager-2.17.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-service-directory-1.11.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-spanner-3.40.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-storage-2.14.0-150400.10.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-cloud-vpc-access-1.10.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-crc32c-1.5.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-google-resumable-media-2.7.0-150400.10.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-googleapis-common-protos-1.62.0-150400.10.4.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-grpc-google-iam-v1-0.13.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-grpcio-status-1.60.1-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-idna-3.4-150400.11.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-idna-3.4-150400.11.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-iniconfig-2.0.0-150400.10.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-iniconfig-2.0.0-150400.10.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-proto-plus-1.23.0-150400.9.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-py-1.11.0-150400.12.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-py-1.11.0-150400.12.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pyOpenSSL-23.2.0-150400.3.10.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pyOpenSSL-23.2.0-150400.3.10.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pyasn1-0.5.0-150400.12.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pyasn1-0.5.0-150400.12.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pyasn1-modules-0.3.0-150400.12.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pyasn1-modules-0.3.0-150400.12.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pycparser-2.21-150400.12.7.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pycparser-2.21-150400.12.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pytz-2023.3-150400.6.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-pytz-2023.3-150400.6.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-requests-2.31.0-150400.6.8.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-requests-2.31.0-150400.6.8.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-rsa-4.9-150400.12.7.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-rsa-4.9-150400.12.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-setuptools-67.7.2-150400.3.12.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-setuptools-67.7.2-150400.3.12.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-sqlparse-0.4.4-150400.6.4.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-urllib3-2.0.7-150400.7.14.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'python311-urllib3-2.0.7-150400.7.14.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libcrc32c-devel-1.1.2-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libcrc32c1-1.1.2-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-apipkg-3.0.1-150400.12.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-cachetools-5.3.1-150400.8.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-certifi-2023.7.22-150400.12.6.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-cffi-1.15.1-150400.8.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-charset-normalizer-3.1.0-150400.9.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-api-core-2.15.0-150400.5.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-auth-2.27.0-150400.6.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-appengine-logging-1.4.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-artifact-registry-1.11.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-audit-log-0.2.5-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-build-3.22.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-compute-1.15.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-core-2.4.1-150400.5.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-dns-0.35.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-domains-1.7.1-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-iam-2.13.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-kms-2.21.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-kms-inventory-0.2.2-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-logging-3.9.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-run-0.10.1-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-secret-manager-2.17.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-service-directory-1.11.1-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-spanner-3.40.1-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-storage-2.14.0-150400.10.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-cloud-vpc-access-1.10.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-crc32c-1.5.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-google-resumable-media-2.7.0-150400.10.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-googleapis-common-protos-1.62.0-150400.10.4.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-grpc-google-iam-v1-0.13.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-grpcio-status-1.60.1-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-idna-3.4-150400.11.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-iniconfig-2.0.0-150400.10.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-proto-plus-1.23.0-150400.9.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-py-1.11.0-150400.12.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pyOpenSSL-23.2.0-150400.3.10.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pyasn1-0.5.0-150400.12.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pyasn1-modules-0.3.0-150400.12.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pycparser-2.21-150400.12.7.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-pytz-2023.3-150400.6.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-requests-2.31.0-150400.6.8.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-rsa-4.9-150400.12.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-setuptools-67.7.2-150400.3.12.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-setuptools-wheel-67.7.2-150400.3.12.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-sqlparse-0.4.4-150400.6.4.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'python311-urllib3-2.0.7-150400.7.14.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcrc32c-devel / libcrc32c1 / python311-apipkg / etc');
}
