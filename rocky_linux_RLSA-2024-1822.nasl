#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:1822.
##

include('compat.inc');

if (description)
{
  script_id(195013);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id(
    "CVE-2024-21011",
    "CVE-2024-21012",
    "CVE-2024-21068",
    "CVE-2024-21085",
    "CVE-2024-21094"
  );
  script_xref(name:"RLSA", value:"2024:1822");

  script_name(english:"Rocky Linux 8 / 9 : java-11-openjdk (RLSA-2024:1822)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as referenced in
the RLSA-2024:1822 advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u401,
    8u401-perf, 11.0.22, 17.0.10, 21.0.2, 22; Oracle GraalVM for JDK: 17.0.10, 21.0.2, 22; Oracle GraalVM
    Enterprise Edition: 20.3.13 and 21.3.9. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability can be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java
    deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets,
    that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox
    for security. (CVE-2024-21011)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Networking). Supported versions that are affected are Oracle Java SE: 11.0.22,
    17.0.10, 21.0.2, 22; Oracle GraalVM for JDK: 17.0.10, 21.0.2, 22; Oracle GraalVM Enterprise Edition:
    20.3.13 and 21.3.9. Difficult to exploit vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise
    Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible
    data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2024-21012)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u401-perf,
    11.0.22, 17.0.10, 21.0.2, 22; Oracle GraalVM for JDK: 17.0.10, 21.0.2 and 22; Oracle GraalVM Enterprise
    Edition: 21.3.9. Difficult to exploit vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise
    Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible
    data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a
    web service which supplies data to the APIs. This vulnerability also applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. (CVE-2024-21068)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Concurrency). Supported versions that are affected are Oracle Java SE: 8u401, 8u401-perf,
    11.0.22; Oracle GraalVM Enterprise Edition: 20.3.13 and 21.3.9. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition.
    Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web
    service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security.
    (CVE-2024-21085)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u401,
    8u401-perf, 11.0.22, 17.0.10, 21.0.2, 22; Oracle GraalVM for JDK: 17.0.10, 21.0.2, 22; Oracle GraalVM
    Enterprise Edition: 20.3.13 and 21.3.9. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise
    Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. (CVE-2024-21094)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:1822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275005");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21094");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-demo-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-demo-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-devel-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-devel-fastdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-devel-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-devel-slowdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-fastdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-headless-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-headless-fastdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-headless-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-headless-slowdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-jmods-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-jmods-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-slowdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-src-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-src-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-static-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-static-libs-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:java-11-openjdk-static-libs-slowdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
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
if (! preg(pattern:"^(8|9)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x / 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'java-11-openjdk-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debuginfo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debuginfo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debugsource-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debugsource-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-fastdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-fastdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-slowdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-slowdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-debuginfo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-debuginfo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-fastdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-fastdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-fastdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-fastdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-fastdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-fastdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-fastdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-fastdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-debuginfo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-debuginfo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-fastdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-fastdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-fastdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-fastdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-fastdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-fastdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-slowdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-slowdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-debuginfo-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-fastdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-fastdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-slowdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-slowdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-slowdebug-11.0.23.0.9-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-slowdebug-11.0.23.0.9-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debuginfo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debuginfo-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debuginfo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debugsource-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debugsource-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-debugsource-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-fastdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-fastdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-slowdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-slowdebug-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-slowdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-debuginfo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-debuginfo-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-debuginfo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-fastdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-fastdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-fastdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-fastdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-slowdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-fastdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-fastdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-fastdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-fastdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-debuginfo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-debuginfo-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-debuginfo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-fastdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-fastdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-fastdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-fastdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-slowdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-fastdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-fastdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-slowdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-slowdebug-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-slowdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-slowdebug-debuginfo-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-fastdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-fastdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-slowdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-slowdebug-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-slowdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-slowdebug-11.0.23.0.9-3.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-slowdebug-11.0.23.0.9-3.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-slowdebug-11.0.23.0.9-3.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-11-openjdk / java-11-openjdk-debuginfo / etc');
}
