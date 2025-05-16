#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228619);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42141");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42141");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: Bluetooth: ISO: Check socket flag
    instead of hcon This fixes the following Smatch static checker warning: net/bluetooth/iso.c:1364
    iso_sock_recvmsg() error: we previously assumed 'pi->conn->hcon' could be null (line 1359)
    net/bluetooth/iso.c 1347 static int iso_sock_recvmsg(struct socket *sock, struct msghdr *msg, 1348 size_t
    len, int flags) 1349 { 1350 struct sock *sk = sock->sk; 1351 struct iso_pinfo *pi = iso_pi(sk); 1352 1353
    BT_DBG(sk %p, sk); 1354 1355 if (test_and_clear_bit(BT_SK_DEFER_SETUP, &bt_sk(sk)->flags)) { 1356
    lock_sock(sk); 1357 switch (sk->sk_state) { 1358 case BT_CONNECT2: 1359 if (pi->conn->hcon &&
    ^^^^^^^^^^^^^^ If ->hcon is NULL 1360 test_bit(HCI_CONN_PA_SYNC, &pi->conn->hcon->flags)) { 1361
    iso_conn_big_sync(sk); 1362 sk->sk_state = BT_LISTEN; 1363 } else { --> 1364
    iso_conn_defer_accept(pi->conn->hcon); ^^^^^^^^^^^^^^ then we're toast 1365 sk->sk_state = BT_CONFIG; 1366
    } 1367 release_sock(sk); 1368 return 0; 1369 case BT_CONNECTED: 1370 if (test_bit(BT_SK_PA_SYNC,
    (CVE-2024-42141)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42141");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

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
    "name": "kernel-rt",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "9"
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
