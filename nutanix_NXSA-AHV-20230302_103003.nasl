#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216474);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id(
    "CVE-2024-4032",
    "CVE-2024-4418",
    "CVE-2024-5564",
    "CVE-2024-5742",
    "CVE-2024-6232",
    "CVE-2024-6345",
    "CVE-2024-6923",
    "CVE-2024-42472",
    "CVE-2024-45490",
    "CVE-2024-45491",
    "CVE-2024-45492"
  );

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20230302.103003)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20230302.102005. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20230302.103003 advisory.

  - An issue was discovered in libexpat before 2.6.3. nextScaffoldPart in xmlparse.c can have an integer
    overflow for m_groupSize on 32-bit platforms (where UINT_MAX equals SIZE_MAX). (CVE-2024-45492)

  - Flatpak is a Linux application sandboxing and distribution framework. Prior to versions 1.14.0 and
    1.15.10, a malicious or compromised Flatpak app using persistent directories could access and write files
    outside of what it would otherwise have access to, which is an attack on integrity and confidentiality.
    When `persistent=subdir` is used in the application permissions (represented as `--persist=subdir` in the
    command-line interface), that means that an application which otherwise doesn't have access to the real
    user home directory will see an empty home directory with a writeable subdirectory `subdir`. Behind the
    scenes, this directory is actually a bind mount and the data is stored in the per-application directory as
    `~/.var/app/$APPID/subdir`. This allows existing apps that are not aware of the per-application directory
    to still work as intended without general home directory access. However, the application does have write
    access to the application directory `~/.var/app/$APPID` where this directory is stored. If the source
    directory for the `persistent`/`--persist` option is replaced by a symlink, then the next time the
    application is started, the bind mount will follow the symlink and mount whatever it points to into the
    sandbox. Partial protection against this vulnerability can be provided by patching Flatpak using the
    patches in commits ceec2ffc and 98f79773. However, this leaves a race condition that could be exploited by
    two instances of a malicious app running in parallel. Closing the race condition requires updating or
    patching the version of bubblewrap that is used by Flatpak to add the new `--bind-fd` option using the
    patch and then patching Flatpak to use it. If Flatpak has been configured at build-time with
    `-Dsystem_bubblewrap=bwrap` (1.15.x) or `--with-system-bubblewrap=bwrap` (1.14.x or older), or a similar
    option, then the version of bubblewrap that needs to be patched is a system copy that is distributed
    separately, typically `/usr/bin/bwrap`. This configuration is the one that is typically used in Linux
    distributions. If Flatpak has been configured at build-time with `-Dsystem_bubblewrap=` (1.15.x) or with
    `--without-system-bubblewrap` (1.14.x or older), then it is the bundled version of bubblewrap that is
    included with Flatpak that must be patched. This is typically installed as `/usr/libexec/flatpak-bwrap`.
    This configuration is the default when building from source code. For the 1.14.x stable branch, these
    changes are included in Flatpak 1.14.10. The bundled version of bubblewrap included in this release has
    been updated to 0.6.3. For the 1.15.x development branch, these changes are included in Flatpak 1.15.10.
    The bundled version of bubblewrap in this release is a Meson wrap subproject, which has been updated to
    0.10.0. The 1.12.x and 1.10.x branches will not be updated for this vulnerability. Long-term support OS
    distributions should backport the individual changes into their versions of Flatpak and bubblewrap, or
    update to newer versions if their stability policy allows it. As a workaround, avoid using applications
    using the `persistent` (`--persist`) permission. (CVE-2024-42472)

  - The ipaddress module contained incorrect information about whether certain IPv4 and IPv6 addresses were
    designated as globally reachable or private. This affected the is_private and is_global properties of
    the ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, and ipaddress.IPv6Network
    classes, where values wouldn't be returned in accordance with the latest information from the IANA
    Special-Purpose Address Registries. CPython 3.12.4 and 3.13.0a6 contain updated information from these
    registries and thus have the intended behavior. (CVE-2024-4032)

  - There is a MEDIUM severity vulnerability affecting CPython. Regular expressions that allowed excessive
    backtracking during tarfile.TarFile header parsing are vulnerable to ReDoS via specifically-crafted tar
    archives. (CVE-2024-6232)

  - There is a MEDIUM severity vulnerability affecting CPython. The email module didn't properly quote
    newlines for email headers when serializing an email message allowing for header injection when an email
    is serialized. (CVE-2024-6923)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20230302.103003
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6622214");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/Node/Version", "Host/Nutanix/Data/Node/Type");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info(node:TRUE);

var constraints = [
  { 'fixed_version' : '20230302.102005', 'product' : 'AHV', 'fixed_display' : 'Upgrade the AHV install to 20230302.102005 or higher.' }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
