#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227624);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-29018");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-29018");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - Moby is an open source container framework that is a key component of Docker Engine, Docker Desktop, and
    other distributions of container tooling or runtimes. Moby's networking implementation allows for many
    networks, each with their own IP address range and gateway, to be defined. This feature is frequently
    referred to as custom networks, as each network can have a different driver, set of parameters and thus
    behaviors. When creating a network, the `--internal` flag is used to designate a network as _internal_.
    The `internal` attribute in a docker-compose.yml file may also be used to mark a network _internal_, and
    other API clients may specify the `internal` parameter as well. When containers with networking are
    created, they are assigned unique network interfaces and IP addresses. The host serves as a router for
    non-internal networks, with a gateway IP that provides SNAT/DNAT to/from container IPs. Containers on an
    internal network may communicate between each other, but are precluded from communicating with any
    networks the host has access to (LAN or WAN) as no default route is configured, and firewall rules are set
    up to drop all outgoing traffic. Communication with the gateway IP address (and thus appropriately
    configured host services) is possible, and the host may communicate with any container IP directly. In
    addition to configuring the Linux kernel's various networking features to enable container networking,
    `dockerd` directly provides some services to container networks. Principal among these is serving as a
    resolver, enabling service discovery, and resolution of names from an upstream resolver. When a DNS
    request for a name that does not correspond to a container is received, the request is forwarded to the
    configured upstream resolver. This request is made from the container's network namespace: the level of
    access and routing of traffic is the same as if the request was made by the container itself. As a
    consequence of this design, containers solely attached to an internal network will be unable to resolve
    names using the upstream resolver, as the container itself is unable to communicate with that nameserver.
    Only the names of containers also attached to the internal network are able to be resolved. Many systems
    run a local forwarding DNS resolver. As the host and any containers have separate loopback devices, a
    consequence of the design described above is that containers are unable to resolve names from the host's
    configured resolver, as they cannot reach these addresses on the host loopback device. To bridge this gap,
    and to allow containers to properly resolve names even when a local forwarding resolver is used on a
    loopback address, `dockerd` detects this scenario and instead forward DNS requests from the host namework
    namespace. The loopback resolver then forwards the requests to its configured upstream resolvers, as
    expected. Because `dockerd` forwards DNS requests to the host loopback device, bypassing the container
    network namespace's normal routing semantics entirely, internal networks can unexpectedly forward DNS
    requests to an external nameserver. By registering a domain for which they control the authoritative
    nameservers, an attacker could arrange for a compromised container to exfiltrate data by encoding it in
    DNS queries that will eventually be answered by their nameservers. Docker Desktop is not affected, as
    Docker Desktop always runs an internal resolver on a RFC 1918 address. Moby releases 26.0.0, 25.0.4, and
    23.0.11 are patched to prevent forwarding any DNS requests from internal networks. As a workaround, run
    containers intended to be solely attached to internal networks with a custom upstream address, which will
    force all upstream DNS queries to be resolved from the container's network namespace. (CVE-2024-29018)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/Ubuntu", "Host/Ubuntu/release");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "docker-doc",
     "docker.io",
     "golang-github-docker-docker-dev"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match_one": {
        "os_version": [
         "11",
         "12"
        ]
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "docker.io",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match_one": {
        "os_version": [
         "20.04",
         "22.04",
         "24.04"
        ]
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
