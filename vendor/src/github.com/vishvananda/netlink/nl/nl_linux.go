// Package nl has low level primitives for making Netlink calls.
package nl

/*
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/param.h>
#include <linux/if_ether.h>
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	// Family type definitions
	FAMILY_ALL         = syscall.AF_UNSPEC
	FAMILY_V4          = syscall.AF_INET
	FAMILY_V6          = syscall.AF_INET6
	SizeofTCMsg        = C.sizeof_struct_tcmsg
	SizeofTcHtbGlob    = C.sizeof_struct_tc_htb_glob
	SizeofTcHtbOpt     = C.sizeof_struct_tc_htb_opt
	SizeofTcU32Sel     = C.sizeof_struct_tc_u32_sel
	SizeofTcU32Key     = C.sizeof_struct_tc_u32_key
	TC_H_ROOT          = C.TC_H_ROOT
	TCA_KIND           = C.TCA_KIND
	TCA_OPTIONS        = C.TCA_OPTIONS
	TCA_HTB_INIT       = C.TCA_HTB_INIT
	TCA_HTB_PARMS      = C.TCA_HTB_PARMS
	TCA_HTB_RTAB       = C.TCA_HTB_RTAB
	TCA_HTB_CTAB       = C.TCA_HTB_CTAB
	TC_H_MAJ_MASK      = C.TC_H_MAJ_MASK
	TC_H_MIN_MASK      = C.TC_H_MIN_MASK
	TC_U32_TERMINAL    = C.TC_U32_TERMINAL
	TCA_U32_CLASSID    = C.TCA_U32_CLASSID
	TCA_U32_SEL        = C.TCA_U32_SEL
	ETH_P_IP           = C.ETH_P_IP
	TIME_UNITS_PER_SEC = 1000000
)

var nextSeqNr uint32
var HZ int
var ClockFactor, TickInUsec float64 = 1, 1
var TcInit bool = false

type TCMsg struct {
	Family  uint8
	X_pad1  uint8
	X_pad2  uint16
	Ifindex int32
	Handle  uint32
	Parent  uint32
	Info    uint32
}

type TcHtbGlob struct {
	Version      uint32
	Rate2quantum uint32
	Defcls       uint32
	Debug        uint32
	Pkts         uint32
}

type TcRatespec struct {
	Log         uint8
	X__reserved uint8
	Overhead    uint16
	Align       int16
	Mpu         uint16
	Rate        uint32
}

type TcHtbOpt struct {
	Rate    TcRatespec
	Ceil    TcRatespec
	Buffer  uint32
	Cbuffer uint32
	Quantum uint32
	Level   uint32
	Prio    uint32
}

type TcU32Sel struct {
	Flags     uint8
	Offshift  uint8
	Nkeys     uint8
	Pad_cgo_0 [1]byte
	Offmask   uint16
	Off       uint16
	Offoff    int16
	Hoff      int16
	Hmask     uint32
	Keys      TcU32Key
}

type TcU32Key struct {
	Mask    uint32
	Val     uint32
	Off     int32
	Offmask int32
}

func init() {
	var t2us, us2t, clockRes uint32
	var line string
	if data, err := ioutil.ReadFile("/proc/net/psched"); err != nil {
		return
	} else {
		line = string(data)
	}

	if n, err := fmt.Sscanf(line, "%x %x %x", &t2us, &us2t, &clockRes); n != 3 || err != nil {
		return
	}

	if t2us == 1000000 {
		HZ = int(us2t)
	} else {
		HZ = int(t2us)
	}
	if HZ == 0 {
		HZ = C.HZ
	}

	if clockRes == 1000000000 {
		t2us = us2t
	}

	ClockFactor = float64(clockRes) / TIME_UNITS_PER_SEC
	TickInUsec = float64(t2us) / float64(us2t) * ClockFactor
	TcInit = true
}

// GetIPFamily returns the family type of a net.IP.
func GetIPFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len {
		return FAMILY_V4
	}
	if ip.To4() != nil {
		return FAMILY_V4
	}
	return FAMILY_V6
}

var nativeEndian binary.ByteOrder

// Get native endianness for the system
func NativeEndian() binary.ByteOrder {
	if nativeEndian == nil {
		var x uint32 = 0x01020304
		if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
			nativeEndian = binary.BigEndian
		} else {
			nativeEndian = binary.LittleEndian
		}
	}
	return nativeEndian
}

// Byte swap a 16 bit value if we aren't big endian
func Swap16(i uint16) uint16 {
	if NativeEndian() == binary.BigEndian {
		return i
	}
	return (i&0xff00)>>8 | (i&0xff)<<8
}

// Byte swap a 32 bit value if aren't big endian
func Swap32(i uint32) uint32 {
	if NativeEndian() == binary.BigEndian {
		return i
	}
	return (i&0xff000000)>>24 | (i&0xff0000)>>8 | (i&0xff00)<<8 | (i&0xff)<<24
}

type NetlinkRequestData interface {
	Len() int
	Serialize() []byte
}

// IfInfomsg is related to links, but it is used for list requests as well
type IfInfomsg struct {
	syscall.IfInfomsg
}

func NewTCMsg(family, handle, parent, index int) *TCMsg {
	return &TCMsg{
		Family:  uint8(family),
		Handle:  uint32(handle << 16),
		Parent:  uint32(parent),
		Ifindex: int32(index),
	}
}

func (msg *TCMsg) Len() int {
	return SizeofTCMsg
}

func (msg *TCMsg) Serialize() []byte {
	return (*(*[SizeofTCMsg]byte)(unsafe.Pointer(msg)))[:]
}

func NewTcHtbGlob(rate2quantum, version, defcls int) *TcHtbGlob {
	return &TcHtbGlob{
		Version:      uint32(version),
		Rate2quantum: uint32(rate2quantum),
		Defcls:       uint32(defcls),
	}
}

func (opt *TcHtbGlob) Len() int {
	return SizeofTcHtbGlob
}

func (opt *TcHtbGlob) Serialize() []byte {
	return (*(*[SizeofTcHtbGlob]byte)(unsafe.Pointer(opt)))[:]
}

func NewTcHtbOpt(rate, ceil, buffer, cbuffer int) *TcHtbOpt {
	return &TcHtbOpt{
		Rate: TcRatespec{
			Rate: uint32(rate),
		},
		Ceil: TcRatespec{
			Rate: uint32(ceil),
		},
		Buffer:  uint32(buffer),
		Cbuffer: uint32(cbuffer),
	}
}

func (opt *TcHtbOpt) Len() int {
	return SizeofTcHtbOpt
}

func (opt *TcHtbOpt) Serialize() []byte {
	return (*(*[SizeofTcHtbOpt]byte)(unsafe.Pointer(opt)))[:]
}

func TcAdjustSize(sz, mpu uint32) uint32 {
	if sz < mpu {
		sz = mpu
	}
	return sz
}

func TcCoreTime2Tick(time uint32) uint32 {
	return uint32(float64(time) * TickInUsec)
}

func TcCalcXmittime(rate, size uint32) uint32 {
	return TcCoreTime2Tick(uint32(TIME_UNITS_PER_SEC * (float64(size) / float64(rate))))
}

func (r *TcRatespec) TcCalcRtable(cellLog int, mtu uint32) (int, [256]uint32) {
	var rtab [256]uint32
	var bps, mpu uint32 = r.Rate, uint32(r.Mpu)
	if mtu == 0 {
		mtu = 2047
	}
	if cellLog < 0 {
		cellLog = 0
		for (mtu >> uint8(cellLog)) > 255 {
			cellLog++
		}
	}
	for i := range rtab {
		sz := TcAdjustSize((uint32(i)+1)<<uint8(cellLog), mpu)
		rtab[i] = TcCalcXmittime(bps, sz)
	}

	r.Align = -1
	r.Log = uint8(cellLog)
	return cellLog, rtab
}

func NewTcU32Sel(flags, nkeys, off int) *TcU32Sel {
	return &TcU32Sel{
		Flags: uint8(flags),
		Nkeys: uint8(nkeys),
		Keys: TcU32Key{
			Off: int32(off),
		},
	}
}

func (sel *TcU32Sel) Len() int {
	return SizeofTcU32Sel
}

func (sel *TcU32Sel) Serialize() []byte {
	return (*(*[SizeofTcU32Sel + SizeofTcU32Key]byte)(unsafe.Pointer(sel)))[:]
}

// Create an IfInfomsg with family specified
func NewIfInfomsg(family int) *IfInfomsg {
	return &IfInfomsg{
		IfInfomsg: syscall.IfInfomsg{
			Family: uint8(family),
		},
	}
}

func DeserializeIfInfomsg(b []byte) *IfInfomsg {
	return (*IfInfomsg)(unsafe.Pointer(&b[0:syscall.SizeofIfInfomsg][0]))
}

func (msg *IfInfomsg) Serialize() []byte {
	return (*(*[syscall.SizeofIfInfomsg]byte)(unsafe.Pointer(msg)))[:]
}

func (msg *IfInfomsg) Len() int {
	return syscall.SizeofIfInfomsg
}

func rtaAlignOf(attrlen int) int {
	return (attrlen + syscall.RTA_ALIGNTO - 1) & ^(syscall.RTA_ALIGNTO - 1)
}

func NlmsgAlignOf(nlmsglen int) int {
	return nlmsgAlignOf(nlmsglen)
}

func nlmsgAlignOf(nlmsglen int) int {
	return (nlmsglen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}

func NewIfInfomsgChild(parent *RtAttr, family int) *IfInfomsg {
	msg := NewIfInfomsg(family)
	parent.children = append(parent.children, msg)
	return msg
}

// Extend RtAttr to handle data and children
type RtAttr struct {
	syscall.RtAttr
	Data     []byte
	children []NetlinkRequestData
}

// Create a new Extended RtAttr object
func NewRtAttr(attrType int, data []byte) *RtAttr {
	return &RtAttr{
		RtAttr: syscall.RtAttr{
			Type: uint16(attrType),
		},
		children: []NetlinkRequestData{},
		Data:     data,
	}
}

// Create a new RtAttr obj anc add it as a child of an existing object
func NewRtAttrChild(parent *RtAttr, attrType int, data []byte) *RtAttr {
	attr := NewRtAttr(attrType, data)
	parent.children = append(parent.children, attr)
	return attr
}

func (a *RtAttr) Len() int {
	if len(a.children) == 0 {
		return (syscall.SizeofRtAttr + len(a.Data))
	}

	l := 0
	for _, child := range a.children {
		l += rtaAlignOf(child.Len())
	}
	l += syscall.SizeofRtAttr
	return rtaAlignOf(l + len(a.Data))
}

// Serialize the RtAttr into a byte array
// This can't ust unsafe.cast because it must iterate through children.
func (a *RtAttr) Serialize() []byte {
	native := NativeEndian()

	length := a.Len()
	buf := make([]byte, rtaAlignOf(length))

	if a.Data != nil {
		copy(buf[4:], a.Data)
	} else {
		next := 4
		for _, child := range a.children {
			childBuf := child.Serialize()
			copy(buf[next:], childBuf)
			next += rtaAlignOf(len(childBuf))
		}
	}

	if l := uint16(length); l != 0 {
		native.PutUint16(buf[0:2], l)
	}
	native.PutUint16(buf[2:4], a.Type)
	return buf
}

type CommonNetlinkRequest interface {
	Serialize() []byte
}

type NetlinkRequest struct {
	syscall.NlMsghdr
	Data []NetlinkRequestData
}

type TcNetlinkRequest struct {
	hdr  syscall.NlMsghdr
	tc   TCMsg
	Data []NetlinkRequestData
}

func (req *TcNetlinkRequest) Len() int {
	return int(req.hdr.Len)
}

func (req *TcNetlinkRequest) Serialize() []byte {
	lenOfhdr := nlmsgAlignOf(syscall.SizeofNlMsghdr) + SizeofTCMsg
	length := lenOfhdr
	dataBytes := make([][]byte, len(req.Data))
	for i, data := range req.Data {
		dataBytes[i] = data.Serialize()
		length = nlmsgAlignOf(length) + len(dataBytes[i])
	}
	req.hdr.Len = uint32(length)
	b := make([]byte, length)
	hdr := (*(*[syscall.SizeofNlMsghdr + SizeofTCMsg]byte)(unsafe.Pointer(req)))[:]

	next := lenOfhdr
	copy(b[0:next], hdr)
	for _, data := range dataBytes {
		copy(b[next:next+len(data)], data)
		next = nlmsgAlignOf(next) + len(data)
	}
	return b
}

func (req *TcNetlinkRequest) AddData(data NetlinkRequestData) {
	if data != nil {
		req.Data = append(req.Data, data)
	}
}

// Serialize the Netlink Request into a byte array
func (req *NetlinkRequest) Serialize() []byte {
	length := syscall.SizeofNlMsghdr
	dataBytes := make([][]byte, len(req.Data))
	for i, data := range req.Data {
		dataBytes[i] = data.Serialize()
		length = length + len(dataBytes[i])
	}
	req.Len = uint32(length)
	b := make([]byte, length)
	hdr := (*(*[syscall.SizeofNlMsghdr]byte)(unsafe.Pointer(req)))[:]
	next := syscall.SizeofNlMsghdr
	copy(b[0:next], hdr)
	for _, data := range dataBytes {
		for _, dataByte := range data {
			b[next] = dataByte
			next = next + 1
		}
	}
	return b
}

func (req *NetlinkRequest) AddData(data NetlinkRequestData) {
	if data != nil {
		req.Data = append(req.Data, data)
	}
}

// Execute the request against a the given sockType.
// Returns a list of netlink messages in seriaized format, optionally filtered
// by resType.
func (req *NetlinkRequest) Execute(sockType int, resType uint16) ([][]byte, error) {
	s, err := getNetlinkSocket(sockType)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	if err := s.Send(req); err != nil {
		return nil, err
	}

	pid, err := s.GetPid()
	if err != nil {
		return nil, err
	}

	var res [][]byte

done:
	for {
		msgs, err := s.Receive()
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != req.Seq {
				return nil, fmt.Errorf("Wrong Seq nr %d, expected 1", m.Header.Seq)
			}
			if m.Header.Pid != pid {
				return nil, fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, pid)
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				native := NativeEndian()
				error := int32(native.Uint32(m.Data[0:4]))
				if error == 0 {
					break done
				}
				fmt.Println("Error ", error)
				return nil, syscall.Errno(-error)
			}
			if resType != 0 && m.Header.Type != resType {
				continue
			}
			res = append(res, m.Data)
			if m.Header.Flags&syscall.NLM_F_MULTI == 0 {
				break done
			}
		}
	}
	return res, nil
}

func (req *TcNetlinkRequest) Execute(sockType int, resType uint16) ([][]byte, error) {
	s, err := getNetlinkSocket(sockType)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	if err := s.Send(req); err != nil {
		return nil, err
	}

	pid, err := s.GetPid()
	if err != nil {
		return nil, err
	}

	var res [][]byte

done:
	for {
		msgs, err := s.Receive()
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != req.hdr.Seq {
				return nil, fmt.Errorf("Wrong Seq nr %d, expected 1", m.Header.Seq)
			}
			if m.Header.Pid != pid {
				return nil, fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, pid)
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				native := NativeEndian()
				error := int32(native.Uint32(m.Data[0:4]))
				if error == 0 {
					break done
				}
				fmt.Println("Error ", error)
				return nil, syscall.Errno(-error)
			}
			if resType != 0 && m.Header.Type != resType {
				continue
			}
			res = append(res, m.Data)
			if m.Header.Flags&syscall.NLM_F_MULTI == 0 {
				break done
			}
		}
	}
	return res, nil
}

// Create a new netlink request from proto and flags
// Note the Len value will be inaccurate once data is added until
// the message is serialized
func NewNetlinkRequest(proto, flags int) *NetlinkRequest {
	return &NetlinkRequest{
		NlMsghdr: syscall.NlMsghdr{
			Len:   uint32(syscall.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: syscall.NLM_F_REQUEST | uint16(flags),
			Seq:   atomic.AddUint32(&nextSeqNr, 1),
		},
	}
}

func NewTcNetlinkRequest(proto, flags, family, index, handle, parent, info int) *TcNetlinkRequest {
	return &TcNetlinkRequest{
		hdr: syscall.NlMsghdr{
			Len:   uint32(syscall.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: syscall.NLM_F_REQUEST | uint16(flags),
			Seq:   atomic.AddUint32(&nextSeqNr, 1),
		},
		tc: TCMsg{
			Family:  uint8(family),
			Ifindex: int32(index),
			Handle:  uint32(handle),
			Parent:  uint32(parent),
			Info:    uint32(info),
		},
	}
}

type NetlinkSocket struct {
	fd  int
	lsa syscall.SockaddrNetlink
}

func TcHMake(maj, min uint32) uint32 {
	return (maj & TC_H_MAJ_MASK) | (min & TC_H_MIN_MASK)
}

func getNetlinkSocket(protocol int) (*NetlinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, protocol)
	if err != nil {
		return nil, err
	}
	s := &NetlinkSocket{
		fd: fd,
	}
	s.lsa.Family = syscall.AF_NETLINK
	if err := syscall.Bind(fd, &s.lsa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return s, nil
}

// Create a netlink socket with a given protocol (e.g. NETLINK_ROUTE)
// and subscribe it to multicast groups passed in variable argument list.
// Returns the netlink socket on which Receive() method can be called
// to retrieve the messages from the kernel.
func Subscribe(protocol int, groups ...uint) (*NetlinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, protocol)
	if err != nil {
		return nil, err
	}
	s := &NetlinkSocket{
		fd: fd,
	}
	s.lsa.Family = syscall.AF_NETLINK

	for _, g := range groups {
		s.lsa.Groups |= (1 << (g - 1))
	}

	if err := syscall.Bind(fd, &s.lsa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return s, nil
}

func (s *NetlinkSocket) Close() {
	syscall.Close(s.fd)
}

func (s *NetlinkSocket) Send(request CommonNetlinkRequest) error {
	if err := syscall.Sendto(s.fd, request.Serialize(), 0, &s.lsa); err != nil {
		return err
	}
	return nil
}

func (s *NetlinkSocket) Receive() ([]syscall.NetlinkMessage, error) {
	rb := make([]byte, syscall.Getpagesize())
	nr, _, err := syscall.Recvfrom(s.fd, rb, 0)
	if err != nil {
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, fmt.Errorf("Got short response from netlink")
	}
	rb = rb[:nr]
	return syscall.ParseNetlinkMessage(rb)
}

func (s *NetlinkSocket) GetPid() (uint32, error) {
	lsa, err := syscall.Getsockname(s.fd)
	if err != nil {
		return 0, err
	}
	switch v := lsa.(type) {
	case *syscall.SockaddrNetlink:
		return v.Pid, nil
	}
	return 0, fmt.Errorf("Wrong socket type")
}

func ZeroTerminated(s string) []byte {
	bytes := make([]byte, len(s)+1)
	for i := 0; i < len(s); i++ {
		bytes[i] = s[i]
	}
	bytes[len(s)] = 0
	return bytes
}

func NonZeroTerminated(s string) []byte {
	bytes := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		bytes[i] = s[i]
	}
	return bytes
}

func BytesToString(b []byte) string {
	n := bytes.Index(b, []byte{0})
	return string(b[:n])
}

func Uint8Attr(v uint8) []byte {
	return []byte{byte(v)}
}

func Uint16Attr(v uint16) []byte {
	native := NativeEndian()
	bytes := make([]byte, 2)
	native.PutUint16(bytes, v)
	return bytes
}

func Uint32Attr(v uint32) []byte {
	native := NativeEndian()
	bytes := make([]byte, 4)
	native.PutUint32(bytes, v)
	return bytes
}

func ParseRouteAttr(b []byte) ([]syscall.NetlinkRouteAttr, error) {
	var attrs []syscall.NetlinkRouteAttr
	for len(b) >= syscall.SizeofRtAttr {
		a, vbuf, alen, err := netlinkRouteAttrAndValue(b)
		if err != nil {
			return nil, err
		}
		ra := syscall.NetlinkRouteAttr{Attr: *a, Value: vbuf[:int(a.Len)-syscall.SizeofRtAttr]}
		attrs = append(attrs, ra)
		b = b[alen:]
	}
	return attrs, nil
}

func netlinkRouteAttrAndValue(b []byte) (*syscall.RtAttr, []byte, int, error) {
	a := (*syscall.RtAttr)(unsafe.Pointer(&b[0]))
	if int(a.Len) < syscall.SizeofRtAttr || int(a.Len) > len(b) {
		return nil, nil, 0, syscall.EINVAL
	}
	return a, b[syscall.SizeofRtAttr:], rtaAlignOf(int(a.Len)), nil
}
