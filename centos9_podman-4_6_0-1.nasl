#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024/03/01.
##

include('compat.inc');

if (description)
{
  script_id(191355);

  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/01");

  script_cve_id(
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-24534",
    "CVE-2023-24536",
    "CVE-2023-24537",
    "CVE-2023-24538",
    "CVE-2023-24539",
    "CVE-2023-24540",
    "CVE-2023-25173",
    "CVE-2023-29400"
  );

  script_name(english:"CentOS 9 : podman-4.6.0-1.el9 (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin was deprecated due to incorrect CVE matches for the build.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=35110");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24540");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:podman");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, 'This plugin has been deprecated.');
