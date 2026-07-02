// Conntrack flush — the kill switch's missing half. Deleting the lan→wan
// forwarding only stops *new* connections: fw4 accepts established flows
// before any zone rule runs, so a download started before the switch would
// keep leaking until it ended on its own. Flushing the kernel's conntrack
// table forces every flow to re-classify as NEW against the now-current
// rules on its next packet. Done over netlink directly (a bare
// IPCTNL_MSG_CT_DELETE is "delete everything"): stock OpenWRT ships no
// conntrack binary, and mistd stays one static binary on purpose.
//
// Needs nf_conntrack_netlink in the kernel — kmod-nf-conntrack-netlink,
// a package DEPENDS (stock images lack it; nfnetlink answers EINVAL for
// the whole subsystem when it is absent, which is this code's telltale
// failure mode on a bare dev router).
package netcfg

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	nfnlSubsysCTNetlink = 1 // NFNL_SUBSYS_CTNETLINK
	ipctnlMsgCtDelete   = 2 // IPCTNL_MSG_CT_DELETE
	nfnetlinkV0         = 0
)

// FlushConntrack empties the connection-tracking table for every family:
// AF_UNSPEC takes ctnetlink's flush-all path (what `conntrack -F` sends),
// avoiding the per-family filter path that newer kernels reject for a
// bare delete. Requires CAP_NET_ADMIN (mistd runs as root on the router).
func FlushConntrack() error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)
	if err := unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}
	if err := ctFlush(sock, 1, unix.AF_UNSPEC); err != nil {
		return fmt.Errorf("conntrack flush: %w", err)
	}
	return nil
}

// ctFlush sends one delete-all request and waits for the kernel's ack.
func ctFlush(sock int, seq uint32, family uint8) error {
	// nlmsghdr (16 bytes) + nfgenmsg (4 bytes), native endianness.
	msg := make([]byte, 20)
	ne := binary.NativeEndian
	ne.PutUint32(msg[0:4], 20)                                       // nlmsg_len
	ne.PutUint16(msg[4:6], nfnlSubsysCTNetlink<<8|ipctnlMsgCtDelete) // nlmsg_type
	ne.PutUint16(msg[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)        // nlmsg_flags
	ne.PutUint32(msg[8:12], seq)                                     // nlmsg_seq
	ne.PutUint32(msg[12:16], 0)                                      // nlmsg_pid (kernel)
	msg[16] = family                                                 // nfgenmsg.nfgen_family
	msg[17] = nfnetlinkV0                                            // nfgenmsg.version
	// msg[18:20]: nfgenmsg.res_id = 0

	if err := unix.Sendto(sock, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, buf, 0)
	if err != nil {
		return err
	}
	if n < 20 || ne.Uint16(buf[4:6]) != unix.NLMSG_ERROR {
		return fmt.Errorf("unexpected netlink reply (len %d, type %d)", n, ne.Uint16(buf[4:6]))
	}
	if code := int32(ne.Uint32(buf[16:20])); code != 0 {
		return unix.Errno(-code)
	}
	return nil
}
