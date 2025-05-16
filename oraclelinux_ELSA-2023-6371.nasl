#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-6371.
##

include('compat.inc');

if (description)
{
  script_id(185821);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2023-1786");

  script_name(english:"Oracle Linux 9 : cloud-init (ELSA-2023-6371)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has a package installed that is affected by a vulnerability as referenced in the
ELSA-2023-6371 advisory.

    [23.1.1-11.0.2]
    - Fix Oracle Datasource network and getdata methods for OCI OL [Orabug: 35950168]

    [23.1.1-11.0.1]
    - Increase retry value and add timeout for OCI [Orabug: 35329883]
    - Fix log file permission [Orabug: 35302969]
    - Update detection logic for OL distros in config template [Orabug: 34845400]
    - Added missing services in rhel/systemd/cloud-init.service [Orabug: 32183938]
    - Added missing services in cloud-init.service.tmpl for sshd [Orabug: 32183938]
    - Forward port applicable cloud-init 18.4-2.0.3 changes to cloud-init-18-5 [Orabug: 30435672]
    - limit permissions [Orabug: 31352433]
    - Changes to ignore all enslaved interfaces [Orabug: 30092148]
    - Make Oracle datasource detect dracut based config files [Orabug: 29956753]
    - add modified version of enable-ec2_utils-to-stop-retrying-to-get-ec2-metadata.patch:
      1. Enable ec2_utils.py having a way to stop retrying to get ec2 metadata
      2. Apply stop retrying to get ec2 metadata to helper/openstack.py MetadataReader
      Resolves: Oracle-Bug:41660 (Bugzilla)
    - added OL to list of known distros

    [23.1.1-11]
    - Resolves: bz#2232296

    [23.1.1-10]
    - Resolves: bz#2229660 bz#2229952

    [23.1.1-9]
    - 0030-NM-renderer-set-default-IPv6-addr-gen-mode-for-all-i.patch [bz#2188388]
    - Resolves: bz#2188388

    [23.1.1-8]
    - 0022-test-fixes-update-tests-to-reflect-AUTOCONNECT_PRIOR.patch [bz#2217865]
    - 0023-test-fixes-remove-NM_CONTROLLED-no-from-tests.patch [bz#2217865]
    - 0024-Revert-limit-permissions-on-def_log_file.patch [bz#2217865]
    - 0025-test-fixes-changes-to-apply-RHEL-specific-config-set.patch [bz#2217865]
    - 0026-Enable-SUSE-based-distros-for-ca-handling-2036.patch [bz#2217865]
    - 0027-Handle-non-existent-ca-cert-config-situation-2073.patch [bz#2217865]
    - 0028-logging-keep-current-file-mode-of-log-file-if-its-st.patch [bz#2222498]
    - 0029-DS-VMware-modify-a-few-log-level-4284.patch [bz#2225374]
    - Resolves: bz#2217865 bz#2222498 bz#2225374

    [23.1.1-7]
    - 0020-Revert-Set-default-renderer-as-sysconfig-for-c9s-RHE.patch
    - 0021-Set-default-renderer-as-sysconfig-for-centos-rhel-41.patch [bz#2209349]
    - Resolves: bz#2209349

    [23.1.1-6]
    - 0011-Revert-Manual-revert-Use-Network-Manager-and-Netplan.patch
    - 0012-Revert-Revert-Add-native-NetworkManager-support-1224.patch
    - 0013-net-sysconfig-do-not-use-the-highest-autoconnect-pri.patch
    - 0014-net-sysconfig-cosmetic-fix-tox-formatting.patch
    - 0015-nm-generate-ipv6-stateful-dhcp-config-at-par-with-sy.patch [bz#2207716]
    - 0016-network_manager-add-a-method-for-ipv6-static-IP-conf.patch [bz#2196284]
    - 0017-net-sysconfig-enable-sysconfig-renderer-if-network-m.patch [bz#2194050]
    - 0018-network-manager-Set-higher-autoconnect-priority-for-.patch [bz#2196231]
    - 0019-Set-default-renderer-as-sysconfig-for-c9s-RHEL-9.patch [bz#2209349]
    - Resolves: bz#2118235 bz#2194050 bz#2196231 bz#2196284 bz#2207716 bz#2209349

    [23.1.1-5]
    - 0010-Do-not-generate-dsa-and-ed25519-key-types-when-crypt.patch [bz#2187164]
    - Resolves: bz#2187164

    [23.1.1-4]
    - 0009-Make-user-vendor-data-sensitive-and-remove-log-permi.patch [bz#2190083]
    - Resolves: bz#2190083

    [23.1.1-3]
    - 0008-Don-t-change-permissions-of-netrules-target-2076.patch [bz#2182948]
    - Resolves: bz#2182948

    [23.1.1-2]
    - 0007-rhel-make-sure-previous-hostname-file-ends-with-a-ne.patch [bz#2184608]
    - Resolves: bz#2184608

    [23.1.1-1]
    - Rebase to 23.1.1 [bz#2172811]
    - Resolves: bz#2172811

    [22.1-9]
    - ci-Allow-growpart-to-resize-encrypted-partitions-1316.patch [bz#2166245]
    - Resolves: bz#2166245
      (Add support for resizing encrypted root volume)

    [22.1-8]
    - ci-cc_set_hostname-ignore-var-lib-cloud-data-set-hostna.patch [bz#2140893]
    - Resolves: bz#2140893
    (systemd[1]: Failed to start Initial cloud-init job after reboot system via sysrq 'b')

    [22.1-7]
    - ci-Ensure-network-ready-before-cloud-init-service-runs-.patch [bz#2152100]
    - Resolves: bz#2152100
      ([RHEL-9] Ensure network ready before cloud-init service runs on RHEL)

    [22.1-6]
    - ci-cloud.cfg.tmpl-make-sure-centos-settings-are-identic.patch [bz#2115565]
    - Resolves: bz#2115565
      (cloud-init configures user 'centos' or 'rhel' instead of 'cloud-user' with cloud-init-22.1)

    [22.1-5]
    - ci-Revert-Add-native-NetworkManager-support-1224.patch [bz#2107463 bz#2104389 bz#2117532 bz#2098501]
    - ci-Revert-Use-Network-Manager-and-Netplan-as-default-re.patch [bz#2107463 bz#2104389 bz#2117532
    bz#2098501]
    - ci-Revert-Revert-Setting-highest-autoconnect-priority-f.patch [bz#2107463 bz#2104389 bz#2117532
    bz#2098501]
    - Resolves: bz#2107463
      ([RHEL-9.1] Cannot run sysconfig when changing the priority of network renderers)
    - Resolves: bz#2104389
      ([RHEL-9.1]Failed to config static IP and IPv6 according to VMware Customization Config File)
    - Resolves: bz#2117532
      ([RHEL9.1] Revert patch of configuring networking by NM keyfiles)
    - Resolves: bz#2098501
      ([RHEL-9.1] IPv6 not workable when cloud-init configure network using NM keyfiles)

    [22.1-4]
    - ci-Honor-system-locale-for-RHEL-1355.patch [bz#2061604]
    - ci-cloud-init.spec-adjust-path-for-66-azure-ephemeral.r.patch [bz#2096270]
    - ci-setup.py-adjust-udev-rules-default-path-1513.patch [bz#2096270]
    - Resolves: bz#2061604
      (cloud-config will change /etc/locale.conf back to en_US.UTF-8 on rhel-guest-image-9.0)
    - Resolves: bz#2096270
      (Adjust udev/rules default path[rhel-9])

    [22.1-3]
    - ci-Support-EC2-tags-in-instance-metadata-1309.patch [bz#2091640]
    - ci-cc_set_hostname-do-not-write-localhost-when-no-hostn.patch [bz#1980403]
    - Resolves: bz#2091640
      ([cloud][init] Add support for reading tags from instance metadata)
    - Resolves: bz#1980403
      ([RHV] RHEL 9 VM with cloud-init without hostname set doesn't result in the FQDN as hostname)

    [22.1-2]
    - ci-Add-native-NetworkManager-support-1224.patch [bz#2056964]
    - ci-Use-Network-Manager-and-Netplan-as-default-renderers.patch [bz#2056964]
    - ci-Revert-Setting-highest-autoconnect-priority-for-netw.patch [bz#2056964]
    - ci-Align-rhel-custom-files-with-upstream-1431.patch [bz#2088448]
    - ci-Remove-rhel-specific-files.patch [bz#2088448]
    - Resolves: bz#2056964
      ([RHEL-9]Rebase cloud-init from Fedora so it can configure networking using NM keyfiles)
    - Resolves: bz#2088448
      (Align cloud.cfg file and systemd with cloud-init upstream .tmpl files)

    [22.1-1]
    - Rebase to 22.1 [bz#2065548]
    - Resolves: bz#2065548
      ([RHEL-9.1] cloud-init rebase to 22.1)

    [21.1-19]
    - ci-Fix-IPv6-netmask-format-for-sysconfig-1215.patch [bz#2053546]
    - ci-Adding-_netdev-to-the-default-mount-configuration.patch [bz#1998445]
    - ci-Setting-highest-autoconnect-priority-for-network-scr.patch [bz#2036060]
    - Resolves: bz#2053546
      (cloud-init writes route6- config with a HEX netmask. ip route does not like : Error: inet6 prefix is
    expected rather than 'fd00:fd00:fd00::/ffff:ffff:ffff:ffff::'.)
    - Resolves: bz#1998445
      ([Azure][RHEL-9] ordering cycle exists after reboot)
    - Resolves: bz#2036060
      ([cloud-init][ESXi][RHEL-9] Failed to config static IP according to VMware Customization Config File)

    [21.1-18]
    - ci-Add-_netdev-option-to-mount-Azure-ephemeral-disk-121.patch [bz#1998445]
    - Resolves: bz#1998445
      ([Azure][RHEL-9] ordering cycle exists after reboot)

    [21.1-17]
    - ci-Add-flexibility-to-IMDS-api-version-793.patch [bz#2042351]
    - ci-Azure-helper-Ensure-Azure-http-handler-sleeps-betwee.patch [bz#2042351]
    - ci-azure-Removing-ability-to-invoke-walinuxagent-799.patch [bz#2042351]
    - ci-Azure-eject-the-provisioning-iso-before-reporting-re.patch [bz#2042351]
    - ci-Azure-Retrieve-username-and-hostname-from-IMDS-865.patch [bz#2042351]
    - ci-Azure-Retry-net-metadata-during-nic-attach-for-non-t.patch [bz#2042351]
    - ci-Azure-adding-support-for-consuming-userdata-from-IMD.patch [bz#2042351]
    - Resolves: bz#2042351
      ([RHEL-9] Support for provisioning Azure VM with userdata)

    [21.1-16]
    - ci-Datasource-for-VMware-953.patch [bz#2040090]
    - ci-Change-netifaces-dependency-to-0.10.4-965.patch [bz#2040090]
    - ci-Update-dscheck_VMware-s-rpctool-check-970.patch [bz#2040090]
    - ci-Revert-unnecesary-lcase-in-ds-identify-978.patch [bz#2040090]
    - ci-Add-netifaces-package-as-a-Requires-in-cloud-init.sp.patch [bz#2040090]
    - Resolves: bz#2040090
      ([cloud-init][RHEL9] Support for cloud-init datasource 'cloud-init-vmware-guestinfo')

    [21.1-15]
    - ci-Add-gdisk-and-openssl-as-deps-to-fix-UEFI-Azure-init.patch [bz#2032524]
    - Resolves: bz#2032524
      ([RHEL9] [Azure] cloud-init fails to configure the system)

    [21.1-14]
    - ci-cloudinit-net-handle-two-different-routes-for-the-sa.patch [bz#2028031]
    - Resolves: bz#2028031
      ([RHEL-9] Above 19.2 of cloud-init fails to configure routes when configuring static and default routes
    to the same destination IP)

    [21.1-13]
    - ci-fix-error-on-upgrade-caused-by-new-vendordata2-attri.patch [bz#2028381]
    - Resolves: bz#2028381
      (cloud-init.service fails to start after package update)

    [21.1-12]
    - ci-remove-unnecessary-EOF-string-in-disable-sshd-keygen.patch [bz#2016305]
    - Resolves: bz#2016305
      (disable-sshd-keygen-if-cloud-init-active.conf:8: Missing '=', ignoring line)

    [21.1-11]
    - ci-cc_ssh.py-fix-private-key-group-owner-and-permission.patch [bz#2015974]
    - Resolves: bz#2015974
      (cloud-init fails to set host key permissions correctly)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-6371.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected cloud-init package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:3:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cloud-init");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('aarch64' >!< cpu) audit(AUDIT_ARCH_NOT, 'aarch64', cpu);

var pkgs = [
    {'reference':'cloud-init-23.1.1-11.0.2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cloud-init');
}
