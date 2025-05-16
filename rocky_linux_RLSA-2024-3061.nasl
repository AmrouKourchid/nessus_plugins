#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:3061.
##

include('compat.inc');

if (description)
{
  script_id(200631);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id("CVE-2020-36518");
  script_xref(name:"RLSA", value:"2024:3061");

  script_name(english:"Rocky Linux 8 : pki-core:10.6 and pki-deps:10.6 (RLSA-2024:3061)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2024:3061 advisory.

    * jackson-databind: denial of service via a large depth of nested objects (CVE-2020-36518)

Tenable has extracted the preceding description block directly from the Rocky Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:3061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2064698");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36518");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apache-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apache-commons-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apache-commons-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bea-stax-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:glassfish-fastinfoset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:glassfish-jaxb-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:glassfish-jaxb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:glassfish-jaxb-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:glassfish-jaxb-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-jss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-jss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-jss-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-ldapjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-ldapjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-acme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-symkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-pki-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:idm-tomcatjss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:jackson-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:jackson-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:jackson-databind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:jackson-jaxrs-json-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:jackson-jaxrs-providers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:javassist-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:jss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pki-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pki-core-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pki-servlet-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-idm-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:resteasy-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slf4j-jdk14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:stax-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:xml-commons-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:xml-commons-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:xmlstreambuffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:xsom");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var appstreams = {
    'pki-core:10.6': [
      {'reference':'apache-commons-collections-3.2.2-10.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-collections-3.2.2-10.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-lang-2.6-21.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-lang-2.6-21.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-net-3.6-3.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-net-3.6-3.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bea-stax-api-1.2.0-16.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-fastinfoset-1.2.13-9.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-api-2.2.12-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-core-2.2.11-12.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-runtime-2.2.11-12.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-txw2-2.2.11-12.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-debuginfo-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-debuginfo-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-javadoc-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-javadoc-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-ldapjdk-4.24.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-ldapjdk-javadoc-4.24.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-acme-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-base-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-base-java-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-ca-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-kra-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-server-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-tomcatjss-7.8.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-annotations-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-core-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-databind-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-json-provider-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-providers-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jakarta-commons-httpclient-3.1-28.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'jakarta-commons-httpclient-3.1-28.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'javassist-3.18.1-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-3.18.1-8.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-javadoc-3.18.1-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-javadoc-3.18.1-8.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-debugsource-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-debugsource-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-core-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-core-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-core-debugsource-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-core-debugsource-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-servlet-engine-9.0.62-1.module+el8.10.0+1767+f923f786', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-idm-pki-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'relaxngDatatype-2011.1-7.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-3.0.26-7.module+el8.10.0+1767+f923f786', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-javadoc-3.0.26-7.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.7.25-4.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.7.25-4.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-jdk14-1.7.25-4.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-jdk14-1.7.25-4.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'stax-ex-1.7.7-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'velocity-1.7-24.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'velocity-1.7-24.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xalan-j2-2.7.1-38.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xalan-j2-2.7.1-38.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xerces-j2-2.11.0-34.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xerces-j2-2.11.0-34.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-apis-1.4.01-25.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-apis-1.4.01-25.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-resolver-1.2-26.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-resolver-1.2-26.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xmlstreambuffer-1.5.4-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xsom-0-19.20110809svn.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ],
    'pki-deps:10.6': [
      {'reference':'apache-commons-collections-3.2.2-10.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-collections-3.2.2-10.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-lang-2.6-21.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-lang-2.6-21.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-net-3.6-3.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'apache-commons-net-3.6-3.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bea-stax-api-1.2.0-16.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-fastinfoset-1.2.13-9.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-api-2.2.12-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-core-2.2.11-12.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-runtime-2.2.11-12.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glassfish-jaxb-txw2-2.2.11-12.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-debuginfo-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-debuginfo-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-javadoc-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-jss-javadoc-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-ldapjdk-4.24.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-ldapjdk-javadoc-4.24.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-acme-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-base-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-base-java-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-ca-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-kra-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-server-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-symkey-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-pki-tools-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'idm-tomcatjss-7.8.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-annotations-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-core-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-databind-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-json-provider-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jackson-jaxrs-providers-2.14.2-1.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jakarta-commons-httpclient-3.1-28.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'jakarta-commons-httpclient-3.1-28.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'javassist-3.18.1-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-3.18.1-8.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-javadoc-3.18.1-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'javassist-javadoc-3.18.1-8.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-debugsource-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jss-debugsource-4.11.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-core-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-core-debuginfo-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-core-debugsource-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-core-debugsource-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-servlet-engine-9.0.62-1.module+el8.10.0+1767+f923f786', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-idm-pki-10.15.0-1.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'relaxngDatatype-2011.1-7.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-3.0.26-7.module+el8.10.0+1767+f923f786', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'resteasy-javadoc-3.0.26-7.module+el8.10.0+1816+f1a7c8eb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.7.25-4.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-1.7.25-4.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-jdk14-1.7.25-4.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slf4j-jdk14-1.7.25-4.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'stax-ex-1.7.7-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'velocity-1.7-24.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'velocity-1.7-24.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xalan-j2-2.7.1-38.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xalan-j2-2.7.1-38.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xerces-j2-2.11.0-34.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xerces-j2-2.11.0-34.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-apis-1.4.01-25.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-apis-1.4.01-25.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-resolver-1.2-26.module+el8.10.0+1763+c7c02164', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xml-commons-resolver-1.2-26.module+el8.3.0+74+855e3f5d', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xmlstreambuffer-1.5.4-8.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xsom-0-19.20110809svn.module+el8.10.0+1763+c7c02164', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
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
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module pki-core:10.6 / pki-deps:10.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-commons-collections / apache-commons-lang / etc');
}
