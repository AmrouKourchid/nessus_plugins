#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:5009. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194294);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2022-27664",
    "CVE-2023-2727",
    "CVE-2023-2728",
    "CVE-2023-29409",
    "CVE-2023-3089",
    "CVE-2023-3153",
    "CVE-2023-3978",
    "CVE-2023-29824",
    "CVE-2023-37788",
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39321",
    "CVE-2023-39322",
    "CVE-2023-39325",
    "CVE-2023-44487"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"RHSA", value:"2023:5009");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"RHEL 8 / 9 : OpenShift Container Platform 4.14.0 (RHSA-2023:5009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.14.0.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:5009 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing Kubernetes application platform solution
    designed for on-premise or private cloud deployments.

    This advisory contains the RPM packages for Red Hat OpenShift Container Platform 4.14.0. See the following
    advisory for the container images for this release:

    https://access.redhat.com/errata/RHSA-2023:5006

    Security Fix(es):

    * golang: net/http, x/net/http2: rapid stream resets can cause excessive work (CVE-2023-44487)
    (CVE-2023-39325)

    * HTTP/2: Multiple HTTP/2 enabled web servers are vulnerable to a DDoS attack (Rapid Reset Attack)
    (CVE-2023-44487)

    * openshift: OCP & FIPS mode (CVE-2023-3089)

    * golang: net/http: handle server errors after sending GOAWAY (CVE-2022-27664)

    * ovn: service monitor MAC flow is not rate limited (CVE-2023-3153)

    * golang.org/x/net/html: Cross site scripting (CVE-2023-3978)

    * scipy: use-after-free in Py_FindObjects() function (CVE-2023-29824)

    * goproxy: Denial of service (DoS) via unspecified vectors. (CVE-2023-37788)

    * golang: html/template:  improper handling of HTML-like comments within script contexts (CVE-2023-39318)

    * golang: html/template: improper handling of special tags within script contexts (CVE-2023-39319)

    * golang: crypto/tls: panic when processing post-handshake message on QUIC connections (CVE-2023-39321)

    * golang: crypto/tls: lack of a limit on buffered post-handshake (CVE-2023-39322)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    All OpenShift Container Platform 4.14 users are advised to upgrade to these updated packages and images
    when they are available in the appropriate release channel. To check for available updates, use the
    OpenShift CLI (oc) or web console. Instructions for upgrading a cluster are available at
    https://docs.openshift.com/container-platform/4.14/updating/updating_a_cluster/updating-cluster-cli.html

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/RHSB-2023-001");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/RHSB-2023-003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2124669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2212085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2221034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243296");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_5009.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c32bd948");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:5009");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.14.0 package based on the guidance in RHSA-2023:5009.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29824");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(327, 79, 400, 416, 770);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:afterburn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:afterburn-dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:catch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:catch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:coreos-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:coreos-installer-bootinfra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:coreos-installer-dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:crun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:crun-wasm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fmt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gmock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gmock-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-prometheus-promu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:google-benchmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:google-benchmark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:google-benchmark-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtest-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition-validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kata-containers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-ipaclones-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nmstate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nmstate-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nmstate-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nmstate-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr-cni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kuryr-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-prometheus-promu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift4-aws-iso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-dnsmasq-tftp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-inspector-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-inspector-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-inspector-dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-ironic-python-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovn23.09");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovn23.09-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovn23.09-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovn23.09-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-automaton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cinderclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cliff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debtcollector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-decorator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-dracclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-fixtures");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-futurist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-glanceclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-hardware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ironic-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ironic-prometheus-exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-keystoneauth1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-keystoneclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-keystonemiddleware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-openstacksdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-os-service-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-os-traits");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-osc-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-cache-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-concurrency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-concurrency-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-db-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-i18n-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-log-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-middleware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-middleware-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-policy-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-rootwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-serialization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-upgradecheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-utils-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-versionedobjects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oslo-versionedobjects-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-osprofiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pbr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-proliantutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pycadf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pycadf-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-requestsexceptions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-scciclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-stevedore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sushy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sushy-oem-idrac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-swiftclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tenacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tooz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wrapt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wrapt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-automaton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cinderclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cliff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cliff-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-debtcollector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-decorator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-dracclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-fixtures");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-futurist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-glanceclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-hardware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-hardware-detect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ironic-inspector-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ironic-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ironic-prometheus-exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ironic-python-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ironic-python-agent-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ironic-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-keystoneauth1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-keystoneclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-keystoneclient-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-keystonemiddleware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-kuryr-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libnmstate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-openstacksdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-openstacksdk-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-os-service-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-os-traits");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-os-traits-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-osc-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-osc-lib-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-cache-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-concurrency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-concurrency-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-context-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-db-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-log-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-messaging-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-middleware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-middleware-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-policy-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-rootwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-rootwrap-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-serialization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-serialization-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-service-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-upgradecheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-utils-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-versionedobjects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-oslo-versionedobjects-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-osprofiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pbr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-proliantutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pycadf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-requestsexceptions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-scciclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-stevedore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sushy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sushy-oem-idrac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sushy-oem-idrac-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sushy-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-swiftclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-tenacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-tooz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-wrapt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-afterburn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spdlog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spdlog-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:toolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wasmedge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wasmedge-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wasmedge-rt");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-27664', 'CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3089', 'CVE-2023-3153', 'CVE-2023-3978', 'CVE-2023-29409', 'CVE-2023-29824', 'CVE-2023-37788', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322', 'CVE-2023-39325', 'CVE-2023-44487');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2023:5009');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/rhocp/4.14/debug',
      'content/dist/layered/rhel8/aarch64/rhocp/4.14/os',
      'content/dist/layered/rhel8/aarch64/rhocp/4.14/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.14/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.14/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.14/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.14/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.14/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.14/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.14/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.14/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.14/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'buildah-1.29.1-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'buildah-tests-1.29.1-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'butane-0.19.0-1.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'butane-redistributable-0.19.0-1.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'conmon-2.1.7-3.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39321']},
      {'reference':'container-selinux-2.221.0-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'containernetworking-plugins-1.0.1-11.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'containers-common-1-51.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'coreos-installer-0.17.0-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'coreos-installer-bootinfra-0.17.0-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'coreos-installer-dracut-0.17.0-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'cri-o-1.27.1-8.1.rhaos4.14.git3fecb83.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'cri-tools-1.27.0-2.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'crun-1.9.2-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'crun-wasm-0.0-3.rhaos4.14.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'crun-wasm-0.0-3.rhaos4.14.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'golang-github-prometheus-promu-0.15.0-15.1.gitd5383c5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'haproxy26-2.6.13-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'nmstate-2.2.12-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'nmstate-devel-2.2.12-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'nmstate-libs-2.2.12-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'nmstate-static-2.2.12-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift-ansible-4.14.0-202310062327.p0.gf781421.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift-ansible-test-4.14.0-202310062327.p0.gf781421.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift-clients-4.14.0-202310191146.p0.g0c63f9d.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-27664', 'CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3978', 'CVE-2023-39325', 'CVE-2023-44487']},
      {'reference':'openshift-clients-redistributable-4.14.0-202310191146.p0.g0c63f9d.assembly.stream.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-27664', 'CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3978', 'CVE-2023-39325', 'CVE-2023-44487']},
      {'reference':'openshift-hyperkube-4.14.0-202310210404.p0.gf67aeb3.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3089', 'CVE-2023-37788', 'CVE-2023-39325', 'CVE-2023-44487']},
      {'reference':'openshift-kuryr-cni-4.14.0-202309272140.p0.g8926a29.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift-kuryr-common-4.14.0-202309272140.p0.g8926a29.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift-kuryr-controller-4.14.0-202309272140.p0.g8926a29.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift-prometheus-promu-0.15.0-15.1.gitd5383c5.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift4-aws-iso-4.14.0-202309272140.p0.gd2acdd5.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'podman-4.4.1-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-29409', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-catatonit-4.4.1-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-docker-4.4.1-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-gvproxy-4.4.1-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-plugins-4.4.1-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-remote-4.4.1-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-tests-4.4.1-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'python3-kuryr-kubernetes-4.14.0-202309272140.p0.g8926a29.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-libnmstate-2.2.12-1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'runc-1.1.9-2.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-29409', 'CVE-2023-39318', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'skopeo-1.11.2-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'skopeo-tests-1.11.2-10.1.rhaos4.14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/rhocp-ironic/4.14/debug',
      'content/dist/layered/rhel9/aarch64/rhocp-ironic/4.14/os',
      'content/dist/layered/rhel9/aarch64/rhocp-ironic/4.14/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/rhocp-ironic/4.14/debug',
      'content/dist/layered/rhel9/ppc64le/rhocp-ironic/4.14/os',
      'content/dist/layered/rhel9/ppc64le/rhocp-ironic/4.14/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhocp-ironic/4.14/debug',
      'content/dist/layered/rhel9/s390x/rhocp-ironic/4.14/os',
      'content/dist/layered/rhel9/s390x/rhocp-ironic/4.14/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhocp-ironic/4.14/debug',
      'content/dist/layered/rhel9/x86_64/rhocp-ironic/4.14/os',
      'content/dist/layered/rhel9/x86_64/rhocp-ironic/4.14/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openstack-ironic-21.5.0-0.20231002130534.0df5961.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openstack-ironic-api-21.5.0-0.20231002130534.0df5961.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openstack-ironic-common-21.5.0-0.20231002130534.0df5961.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openstack-ironic-conductor-21.5.0-0.20231002130534.0df5961.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openstack-ironic-dnsmasq-tftp-server-21.5.0-0.20231002130534.0df5961.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openstack-ironic-inspector-11.5.0-0.20230706175125.193aa0d.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openstack-ironic-inspector-api-11.5.0-0.20230706175125.193aa0d.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openstack-ironic-inspector-conductor-11.5.0-0.20230706175125.193aa0d.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openstack-ironic-inspector-dnsmasq-11.5.0-0.20230706175125.193aa0d.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openstack-ironic-python-agent-9.5.0-0.20230728140546.fce0b8c.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-oslo-cache-lang-3.4.0-0.20230608153448.a720016.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-oslo-concurrency-lang-5.1.1-0.20230706190204.0af5942.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-oslo-db-lang-12.3.1-0.20230608142355.b689b63.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-oslo-i18n-lang-6.0.0-0.20230608140652.03605c2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-oslo-log-lang-5.2.0-0.20230608150750.16a8a42.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-oslo-middleware-lang-5.1.1-0.20230608145931.7725ac9.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-oslo-policy-lang-4.2.0-0.20230608153320.93129eb.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-oslo-utils-lang-6.1.0-0.20230608142355.d49d594.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-oslo-versionedobjects-lang-3.1.0-0.20230608141554.b4ea834.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-pycadf-common-3.1.1-0.20230308171749.4179996.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python-wrapt-doc-1.14.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-automaton-3.1.0-0.20230608140652.a4f7631.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-cinderclient-9.3.0-0.20230608143053.f7a612e.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-cliff-4.3.0-0.20230608150702.72e81d7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-cliff-tests-4.3.0-0.20230608150702.72e81d7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-debtcollector-2.5.0-0.20230308172820.a6b46c5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-decorator-4.4.2-6.0.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-dracclient-8.0.0-0.20230308200614.9c7499c.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-fixtures-4.0.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-futurist-2.4.1-0.20230308173923.159d752.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-glanceclient-4.3.0-0.20230608143056.52fb6b2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-hardware-0.30.0-0.20230308190813.f6ff0ed.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-hardware-detect-0.30.0-0.20230308190813.f6ff0ed.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-ironic-inspector-tests-11.5.0-0.20230706175125.193aa0d.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-ironic-lib-5.4.1-0.20230706172632.25d8671.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-ironic-prometheus-exporter-4.1.1-0.20230614150617.7b35627.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-ironic-python-agent-9.5.0-0.20230728140546.fce0b8c.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-ironic-python-agent-tests-9.5.0-0.20230728140546.fce0b8c.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-ironic-tests-21.5.0-0.20231002130534.0df5961.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-keystoneauth1-5.2.0-0.20230608152518.2e40bbf.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-keystoneclient-5.1.0-0.20230608141554.4763cd8.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-keystoneclient-tests-5.1.0-0.20230608141554.4763cd8.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-keystonemiddleware-10.3.0-0.20230608151410.92cdf8a.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-openstacksdk-1.2.0-0.20230608155226.b7ff031.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-openstacksdk-tests-1.2.0-0.20230608155226.b7ff031.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-os-service-types-1.7.0-0.20230308170555.0b2f473.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-os-traits-3.0.0-0.20230608152745.cff125c.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-os-traits-tests-3.0.0-0.20230608152745.cff125c.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-osc-lib-2.8.0-0.20230608151456.db9cdc9.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-osc-lib-tests-2.8.0-0.20230608151456.db9cdc9.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-cache-3.4.0-0.20230608153448.a720016.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-cache-tests-3.4.0-0.20230608153448.a720016.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-concurrency-5.1.1-0.20230706190204.0af5942.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-concurrency-tests-5.1.1-0.20230706190204.0af5942.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-config-9.1.1-0.20230608145954.515daab.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-context-5.1.1-0.20230608143931.7696282.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-context-tests-5.1.1-0.20230608143931.7696282.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-db-12.3.1-0.20230608142355.b689b63.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-db-tests-12.3.1-0.20230608142355.b689b63.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-i18n-6.0.0-0.20230608140652.03605c2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-log-5.2.0-0.20230608150750.16a8a42.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-log-tests-5.2.0-0.20230608150750.16a8a42.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-messaging-14.3.1-0.20230608152013.0602d1a.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-messaging-tests-14.3.1-0.20230608152013.0602d1a.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-middleware-5.1.1-0.20230608145931.7725ac9.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-middleware-tests-5.1.1-0.20230608145931.7725ac9.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-policy-4.2.0-0.20230608153320.93129eb.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-policy-tests-4.2.0-0.20230608153320.93129eb.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-rootwrap-7.0.1-0.20230608144658.b72372b.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-rootwrap-tests-7.0.1-0.20230608144658.b72372b.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-serialization-5.1.1-0.20230608144505.b4be3a4.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-serialization-tests-5.1.1-0.20230608144505.b4be3a4.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-service-3.1.1-0.20230608145222.b3ba591.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-service-tests-3.1.1-0.20230608145222.b3ba591.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-upgradecheck-2.1.1-0.20230608143829.eeedfc9.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-utils-6.1.0-0.20230608142355.d49d594.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-utils-tests-6.1.0-0.20230608142355.d49d594.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-versionedobjects-3.1.0-0.20230608141554.b4ea834.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-oslo-versionedobjects-tests-3.1.0-0.20230608141554.b4ea834.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-osprofiler-3.4.3-0.20230308173821.3286301.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-pbr-5.11.1-0.1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-proliantutils-2.14.1-0.20230608154738.3de2844.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-pycadf-3.1.1-0.20230308171749.4179996.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-requestsexceptions-1.4.0-0.20230308170555.d7ac0ff.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-scciclient-0.12.3-0.20230308201513.0940a71.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-stevedore-5.1.0-0.20230608154210.2d99ccc.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-sushy-4.5.0-0.20230719180619.146ed33.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-sushy-oem-idrac-5.0.0-0.20230308202122.da9a0e4.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-sushy-oem-idrac-tests-5.0.0-0.20230308202122.da9a0e4.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-sushy-tests-4.5.0-0.20230719180619.146ed33.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-swiftclient-4.3.0-0.20230608151934.236c277.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-tenacity-6.3.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-tooz-4.1.0-0.20230608154038.d5bf20c.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'python3-wrapt-1.14.1-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/rhocp/4.14/debug',
      'content/dist/layered/rhel9/aarch64/rhocp/4.14/os',
      'content/dist/layered/rhel9/aarch64/rhocp/4.14/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.14/debug',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.14/os',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.14/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhocp/4.14/debug',
      'content/dist/layered/rhel9/s390x/rhocp/4.14/os',
      'content/dist/layered/rhel9/s390x/rhocp/4.14/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhocp/4.14/debug',
      'content/dist/layered/rhel9/x86_64/rhocp/4.14/os',
      'content/dist/layered/rhel9/x86_64/rhocp/4.14/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'afterburn-5.4.3-1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'afterburn-dracut-5.4.3-1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'bpftool-7.0.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'buildah-1.29.1-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'buildah-tests-1.29.1-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'catch-3.3.2-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'catch-devel-3.3.2-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'conmon-2.1.7-3.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39321']},
      {'reference':'container-selinux-2.221.0-2.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'coreos-installer-0.17.0-1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'coreos-installer-bootinfra-0.17.0-1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'coreos-installer-dracut-0.17.0-1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'cri-o-1.27.1-8.1.rhaos4.14.git3fecb83.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'cri-tools-1.27.0-2.1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'crun-1.9.2-1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'crun-wasm-1.8.5-3.rhaos4.14.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'crun-wasm-1.8.5-3.rhaos4.14.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'fmt-9.1.0-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'fmt-devel-9.1.0-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'gmock-1.13.0-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'gmock-devel-1.13.0-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'google-benchmark-1.8.2-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-29824']},
      {'reference':'google-benchmark-devel-1.8.2-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-29824']},
      {'reference':'google-benchmark-doc-1.8.2-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-29824']},
      {'reference':'gtest-1.13.0-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'gtest-devel-1.13.0-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'ignition-2.16.2-1.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'ignition-validate-2.16.2-1.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kata-containers-3.1.3-4.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-core-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-debug-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-debug-core-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-debug-devel-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-debug-devel-matched-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-debug-modules-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-debug-modules-core-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-debug-modules-extra-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-debug-modules-internal-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-debug-modules-partner-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-devel-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-devel-matched-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-modules-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-modules-core-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-modules-extra-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-modules-internal-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-64k-modules-partner-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-core-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-cross-headers-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-core-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-devel-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-devel-matched-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-modules-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-modules-core-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-modules-extra-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-modules-internal-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-modules-partner-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-debug-uki-virt-5.14.0-284.36.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-devel-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-devel-matched-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-headers-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-ipaclones-internal-5.14.0-284.36.1.el9_2', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-ipaclones-internal-5.14.0-284.36.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-modules-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-modules-core-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-modules-extra-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-modules-internal-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-modules-partner-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-core-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-core-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-devel-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-devel-matched-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-kvm-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-modules-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-modules-core-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-modules-extra-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-modules-internal-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-debug-modules-partner-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-devel-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-devel-matched-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-kvm-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-modules-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-modules-core-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-modules-extra-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-modules-internal-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-modules-partner-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-rt-selftests-internal-5.14.0-284.36.1.rt14.321.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-selftests-internal-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-tools-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-tools-libs-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-tools-libs-5.14.0-284.36.1.el9_2', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-tools-libs-5.14.0-284.36.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.36.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.36.1.el9_2', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.36.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-uki-virt-5.14.0-284.36.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-zfcpdump-5.14.0-284.36.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-zfcpdump-core-5.14.0-284.36.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-zfcpdump-devel-5.14.0-284.36.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-zfcpdump-devel-matched-5.14.0-284.36.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-zfcpdump-modules-5.14.0-284.36.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-zfcpdump-modules-core-5.14.0-284.36.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-zfcpdump-modules-extra-5.14.0-284.36.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-zfcpdump-modules-internal-5.14.0-284.36.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'kernel-zfcpdump-modules-partner-5.14.0-284.36.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift-ansible-4.14.0-202310062327.p0.gf781421.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift-ansible-test-4.14.0-202310062327.p0.gf781421.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'openshift-clients-4.14.0-202310191146.p0.g0c63f9d.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-27664', 'CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3978', 'CVE-2023-39325', 'CVE-2023-44487']},
      {'reference':'openshift-clients-redistributable-4.14.0-202310191146.p0.g0c63f9d.assembly.stream.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-27664', 'CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3978', 'CVE-2023-39325', 'CVE-2023-44487']},
      {'reference':'openshift-hyperkube-4.14.0-202310210404.p0.gf67aeb3.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3089', 'CVE-2023-37788', 'CVE-2023-39325', 'CVE-2023-44487']},
      {'reference':'ovn23.09-23.09.0-37.el9fdp', 'release':'9', 'el_string':'el9fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3153']},
      {'reference':'ovn23.09-central-23.09.0-37.el9fdp', 'release':'9', 'el_string':'el9fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3153']},
      {'reference':'ovn23.09-host-23.09.0-37.el9fdp', 'release':'9', 'el_string':'el9fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3153']},
      {'reference':'ovn23.09-vtep-23.09.0-37.el9fdp', 'release':'9', 'el_string':'el9fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-3153']},
      {'reference':'perf-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'podman-4.4.1-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-29409', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-docker-4.4.1-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-gvproxy-4.4.1-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-plugins-4.4.1-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-remote-4.4.1-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'podman-tests-4.4.1-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'python3-perf-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'rtla-5.14.0-284.36.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'runc-1.1.9-2.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-29409', 'CVE-2023-39318', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'skopeo-1.11.2-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'skopeo-tests-1.11.2-10.1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728', 'CVE-2023-39318', 'CVE-2023-39319', 'CVE-2023-39321', 'CVE-2023-39322']},
      {'reference':'spdlog-1.12.0-1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'spdlog-devel-1.12.0-1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'toolbox-0.1.2-1.rhaos4.14.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'wasmedge-0.12.1-2.rhaos4.14.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'wasmedge-0.12.1-2.rhaos4.14.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'wasmedge-devel-0.12.1-2.rhaos4.14.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'wasmedge-devel-0.12.1-2.rhaos4.14.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'wasmedge-rt-0.12.1-2.rhaos4.14.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']},
      {'reference':'wasmedge-rt-0.12.1-2.rhaos4.14.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-2727', 'CVE-2023-2728']}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'afterburn / afterburn-dracut / bpftool / buildah / buildah-tests / etc');
}
