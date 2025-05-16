#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1639-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(197047);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/15");

  script_cve_id("CVE-2023-28858", "CVE-2023-28859");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1639-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : python-arcomplete, python-Fabric, python-PyGithub, python-antlr4-python3-runtime, python-avro, python-chardet, python-distro, python-docker, python-fakeredis, python-fixedint, python-httplib2, python-httpretty, python-javaproperties, python-jsondiff, python-knack, python-marshmallow, python-opencensus, python-opencensus-context, python-opencensus-ext-threading, python-opentelemetry-api, python-opentelemetry-sdk, python-opentelemetry-semantic-conventions, python-opentelemetry-test-utils, python-pycomposefile, python-pydash, python-redis, python-retrying, python-semver, python-sshtunnel, python-strictyaml, python-sure, python-vcrpy, python-xmltodict (SUSE-SU-2024:1639-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:1639-1 advisory.

  - redis-py before 4.5.3 leaves a connection open after canceling an async Redis command at an inopportune
    time, and can send response data to the client of an unrelated request in an off-by-one manner. NOTE: this
    CVE Record was initially created in response to reports about ChatGPT, and 4.3.6, 4.4.3, and 4.5.3 were
    released (changing the behavior for pipeline operations); however, please see CVE-2023-28859 about
    addressing data leakage across AsyncIO connections in general. (CVE-2023-28858)

  - redis-py before 4.4.4 and 4.5.x before 4.5.4 leaves a connection open after canceling an async Redis
    command at an inopportune time, and can send response data to the client of an unrelated request. (This
    could, for example, happen for a non-pipeline operation.) NOTE: the solutions for CVE-2023-28859 address
    data leakage across AsyncIO connections in general. (CVE-2023-28859)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/761162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222880");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035268.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28859");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28859");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-paramiko-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tqdm-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Automat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Deprecated");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Fabric");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-PyGithub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-PyJWT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-all_non_platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-conch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-conch_nacl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-contextvars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-Twisted-tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aiosignal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-antlr4-python3-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-argcomplete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-asgiref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-async_timeout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-blinker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-constantly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-decorator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-fakeredis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-fixedint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-fluidity-sm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-frozenlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-httplib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-httpretty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-humanfriendly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-hyperlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-importlib-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-incremental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-invoke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-isodate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-javaproperties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-jsondiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-knack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-lexicon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-marshmallow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-multidict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-oauthlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opencensus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opencensus-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opencensus-ext-threading");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opentelemetry-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opentelemetry-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opentelemetry-semantic-conventions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-opentelemetry-test-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-paramiko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pathspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pkginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-portalocker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pycomposefile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pydash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-requests-oauthlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-retrying");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-semver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-service_identity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-sortedcontainers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-sshtunnel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-strictyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-sure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-tabulate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-tqdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-typing_extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-vcrpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-websocket-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-wrapt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-xmltodict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-yarl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-zipp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-zope.interface");
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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-Fabric-3.2.2-150400.10.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-PyGithub-1.57-150400.10.4.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-antlr4-python3-runtime-4.13.1-150400.10.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-asgiref-3.6.0-150400.9.7.3', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-avro-1.11.3-150400.10.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-distro-1.9.0-150400.12.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-docker-7.0.0-150400.8.4.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-fakeredis-2.21.0-150400.9.3.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-fixedint-0.2.0-150400.9.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-httplib2-0.22.0-150400.10.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-httpretty-1.1.4-150400.11.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-javaproperties-0.8.1-150400.10.4.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-jsondiff-2.0.0-150400.10.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-knack-0.11.0-150400.10.4.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-marshmallow-3.20.2-150400.9.7.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-opencensus-0.11.4-150400.10.6.3', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-opencensus-context-0.1.3-150400.10.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-opencensus-ext-threading-0.1.2-150400.10.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-opentelemetry-sdk-1.23.0-150400.9.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-opentelemetry-semantic-conventions-0.44b0-150400.9.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-opentelemetry-test-utils-0.44b0-150400.9.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-pycomposefile-0.0.30-150400.9.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-pydash-6.0.2-150400.9.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-redis-5.0.1-150400.12.4.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-retrying-1.3.4-150400.12.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-semver-3.0.2-150400.10.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-sshtunnel-0.4.0-150400.5.4.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-strictyaml-1.7.3-150400.9.3.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-sure-2.0.1-150400.12.4.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-typing_extensions-4.5.0-150400.3.9.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-vcrpy-6.0.1-150400.7.4.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-wheel-0.40.0-150400.13.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-xmltodict-0.13.0-150400.12.4.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-zipp-3.15.0-150400.10.7.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Fabric-3.2.2-150400.10.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-PyGithub-1.57-150400.10.4.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-antlr4-python3-runtime-4.13.1-150400.10.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-asgiref-3.6.0-150400.9.7.3', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-avro-1.11.3-150400.10.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-distro-1.9.0-150400.12.4.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-distro-1.9.0-150400.12.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-docker-7.0.0-150400.8.4.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-fakeredis-2.21.0-150400.9.3.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-fixedint-0.2.0-150400.9.3.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-httplib2-0.22.0-150400.10.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-httpretty-1.1.4-150400.11.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-javaproperties-0.8.1-150400.10.4.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-jsondiff-2.0.0-150400.10.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-knack-0.11.0-150400.10.4.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-marshmallow-3.20.2-150400.9.7.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-opencensus-0.11.4-150400.10.6.3', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-opencensus-context-0.1.3-150400.10.6.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-opencensus-ext-threading-0.1.2-150400.10.6.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-opentelemetry-sdk-1.23.0-150400.9.3.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-opentelemetry-semantic-conventions-0.44b0-150400.9.3.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-opentelemetry-test-utils-0.44b0-150400.9.3.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pycomposefile-0.0.30-150400.9.3.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pydash-6.0.2-150400.9.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-redis-5.0.1-150400.12.4.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-retrying-1.3.4-150400.12.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-semver-3.0.2-150400.10.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-sshtunnel-0.4.0-150400.5.4.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-strictyaml-1.7.3-150400.9.3.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-sure-2.0.1-150400.12.4.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-typing_extensions-4.5.0-150400.3.9.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-typing_extensions-4.5.0-150400.3.9.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-vcrpy-6.0.1-150400.7.4.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-wheel-0.40.0-150400.13.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-wheel-0.40.0-150400.13.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-xmltodict-0.13.0-150400.12.4.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-zipp-3.15.0-150400.10.7.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-zipp-3.15.0-150400.10.7.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-Fabric-3.2.2-150400.10.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-PyGithub-1.57-150400.10.4.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-antlr4-python3-runtime-4.13.1-150400.10.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-asgiref-3.6.0-150400.9.7.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-avro-1.11.3-150400.10.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-distro-1.9.0-150400.12.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-docker-7.0.0-150400.8.4.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-fakeredis-2.21.0-150400.9.3.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-fixedint-0.2.0-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-httplib2-0.22.0-150400.10.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-httpretty-1.1.4-150400.11.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-javaproperties-0.8.1-150400.10.4.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-jsondiff-2.0.0-150400.10.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-knack-0.11.0-150400.10.4.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-marshmallow-3.20.2-150400.9.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-opencensus-0.11.4-150400.10.6.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-opencensus-context-0.1.3-150400.10.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-opencensus-ext-threading-0.1.2-150400.10.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-opentelemetry-sdk-1.23.0-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-opentelemetry-semantic-conventions-0.44b0-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-opentelemetry-test-utils-0.44b0-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-pycomposefile-0.0.30-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-pydash-6.0.2-150400.9.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-redis-5.0.1-150400.12.4.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-retrying-1.3.4-150400.12.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-semver-3.0.2-150400.10.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-sshtunnel-0.4.0-150400.5.4.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-strictyaml-1.7.3-150400.9.3.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-sure-2.0.1-150400.12.4.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-typing_extensions-4.5.0-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-vcrpy-6.0.1-150400.7.4.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-wheel-0.40.0-150400.13.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-xmltodict-0.13.0-150400.12.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-zipp-3.15.0-150400.10.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Fabric-3.2.2-150400.10.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-PyGithub-1.57-150400.10.4.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-antlr4-python3-runtime-4.13.1-150400.10.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-asgiref-3.6.0-150400.9.7.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-avro-1.11.3-150400.10.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-distro-1.9.0-150400.12.4.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-distro-1.9.0-150400.12.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-docker-7.0.0-150400.8.4.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-fakeredis-2.21.0-150400.9.3.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-fixedint-0.2.0-150400.9.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-httplib2-0.22.0-150400.10.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-httpretty-1.1.4-150400.11.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-javaproperties-0.8.1-150400.10.4.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-jsondiff-2.0.0-150400.10.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-knack-0.11.0-150400.10.4.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-marshmallow-3.20.2-150400.9.7.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-opencensus-0.11.4-150400.10.6.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-opencensus-context-0.1.3-150400.10.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-opencensus-ext-threading-0.1.2-150400.10.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-opentelemetry-sdk-1.23.0-150400.9.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-opentelemetry-semantic-conventions-0.44b0-150400.9.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-opentelemetry-test-utils-0.44b0-150400.9.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pycomposefile-0.0.30-150400.9.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pydash-6.0.2-150400.9.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-redis-5.0.1-150400.12.4.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-retrying-1.3.4-150400.12.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-semver-3.0.2-150400.10.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-sshtunnel-0.4.0-150400.5.4.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-strictyaml-1.7.3-150400.9.3.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-sure-2.0.1-150400.12.4.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-typing_extensions-4.5.0-150400.3.9.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-typing_extensions-4.5.0-150400.3.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-vcrpy-6.0.1-150400.7.4.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-wheel-0.40.0-150400.13.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-wheel-0.40.0-150400.13.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-xmltodict-0.13.0-150400.12.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-zipp-3.15.0-150400.10.7.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-zipp-3.15.0-150400.10.7.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python-paramiko-doc-3.4.0-150400.13.10.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python-tqdm-bash-completion-4.66.1-150400.9.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Automat-22.10.0-150400.3.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Deprecated-1.2.14-150400.10.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-PyJWT-2.8.0-150400.8.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Pygments-2.15.1-150400.7.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-all_non_platform-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-conch-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-conch_nacl-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-contextvars-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-http2-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-serial-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-Twisted-tls-22.10.0-150400.5.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.18.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-aiosignal-1.3.1-150400.9.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-argcomplete-3.3.0-150400.12.12.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-async_timeout-4.0.2-150400.10.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-blinker-1.6.2-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-chardet-5.2.0-150400.13.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-constantly-15.1.0-150400.12.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-decorator-5.1.1-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-distro-1.9.0-150400.12.4.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-fluidity-sm-0.2.0-150400.10.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-frozenlist-1.3.3-150400.9.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-humanfriendly-10.0-150400.13.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-hyperlink-21.0.0-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-importlib-metadata-6.8.0-150400.10.9.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-incremental-22.10.0-150400.3.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-invoke-2.1.2-150400.10.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-isodate-0.6.1-150400.12.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-lexicon-2.0.1-150400.10.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-multidict-6.0.4-150400.7.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-oauthlib-3.2.2-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-opentelemetry-api-1.23.0-150400.10.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-paramiko-3.4.0-150400.13.10.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pathspec-0.11.1-150400.9.7.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pip-22.3.1-150400.17.16.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pkginfo-1.9.6-150400.7.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-portalocker-2.7.0-150400.10.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-psutil-5.9.5-150400.6.9.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-pyparsing-3.0.9-150400.5.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-requests-oauthlib-1.3.1-150400.12.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-scp-0.14.5-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-service_identity-23.1.0-150400.8.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-sortedcontainers-2.4.0-150400.8.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-tabulate-0.9.0-150400.11.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-tqdm-4.66.1-150400.9.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-typing_extensions-4.5.0-150400.3.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-websocket-client-1.5.1-150400.13.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-wheel-0.40.0-150400.13.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-wrapt-1.15.0-150400.12.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-yarl-1.9.2-150400.8.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-zipp-3.15.0-150400.10.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-zope.interface-6.0-150400.12.7.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-paramiko-doc / python-tqdm-bash-completion / etc');
}
