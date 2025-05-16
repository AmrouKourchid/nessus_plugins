#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2017-1308-1.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-13081.
##

include('compat.inc');

if (description)
{
  script_id(180812);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2016-7910",
    "CVE-2016-8646",
    "CVE-2016-10208",
    "CVE-2017-5986",
    "CVE-2017-7308"
  );

  script_name(english:"Oracle Linux 7 : ELSA-2017-1308-1: / kernel (ELSA-2017-13081) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2017-13081 advisory.

  - The hash_accept function in crypto/algif_hash.c in the Linux kernel before 4.3.6 allows local users to
    cause a denial of service (OOPS) by attempting to trigger use of in-kernel hash algorithms for a socket
    that has received zero bytes of data. (CVE-2016-8646)

  - Use-after-free vulnerability in the disk_seqf_stop function in block/genhd.c in the Linux kernel before
    4.7.1 allows local users to gain privileges by leveraging the execution of a certain stop operation even
    if the corresponding start operation had failed. (CVE-2016-7910)

  - The ext4_fill_super function in fs/ext4/super.c in the Linux kernel through 4.9.8 does not properly
    validate meta block groups, which allows physically proximate attackers to cause a denial of service (out-
    of-bounds read and system crash) via a crafted ext4 image. (CVE-2016-10208)

  - Race condition in the sctp_wait_for_sndbuf function in net/sctp/socket.c in the Linux kernel before 4.9.11
    allows local users to cause a denial of service (assertion failure and panic) via a multithreaded
    application that peels off an association in a certain buffer-full state. (CVE-2017-5986)

  - The packet_set_ring function in net/packet/af_packet.c in the Linux kernel through 4.10.6 does not
    properly validate certain block-size data, which allows local users to cause a denial of service (integer
    signedness error and out-of-bounds write), or gain privileges (if the CAP_NET_RAW capability is held), via
    crafted system calls. (CVE-2017-7308)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2017-1308-1.nasl (plugin ID 100506).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-1308-1.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7910");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7308");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2017-1308-1.nasl (plugin ID 100506) instead.");
