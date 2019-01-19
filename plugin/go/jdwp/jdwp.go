package jdwp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

type Protocol struct {
	Format []string
}

//封包
func (p *Protocol) Pack(args ...interface{}) []byte {
	la := len(args)
	ls := len(p.Format)
	ret := []byte{}
	if ls > 0 && la > 0 && ls == la {
		for i := 0; i < ls; i++ {
			if p.Format[i] == "H" {
				ret = append(ret, IntToBytes2(args[i].(int))...)
			} else if p.Format[i] == "I" {
				ret = append(ret, IntToBytes4(args[i].(int))...)
			} else if strings.Contains(p.Format[i], "s") {
				num, _ := strconv.Atoi(strings.TrimRight(p.Format[i], "s"))
				ret = append(ret, []byte(fmt.Sprintf("%s%s", args[i].(string), strings.Repeat("\x00", num-len(args[i].(string)))))...)
			} else if strings.Contains(p.Format[i], "c") {
				ret = append(ret, args[i].(byte))
			}
		}
	}
	return ret
}

//解包
func (p *Protocol) UnPack(msg []byte) []interface{} {
	la := len(p.Format)
	ret := make([]interface{}, la)
	if la > 0 {
		for i := 0; i < la; i++ {
			if p.Format[i] == "H" {
				ret[i] = Bytes4ToInt(msg[0:2])
				msg = msg[2:len(msg)]
			} else if p.Format[i] == "I" {
				ret[i] = Bytes4ToInt(msg[0:4])
				msg = msg[4:len(msg)]
			} else if strings.Contains(p.Format[i], "s") {
				num, _ := strconv.Atoi(strings.TrimRight(p.Format[i], "s"))
				ret[i] = string(msg[0:num])
				msg = msg[num:len(msg)]

			} else if strings.Contains(p.Format[i], "c") {
				ret[i] = msg[0]
				msg = msg[1:len(msg)]
			}
		}
	}
	return ret
}

func (p *Protocol) Size() int {
	size := 0
	ls := len(p.Format)
	if ls > 0 {
		for i := 0; i < ls; i++ {
			if p.Format[i] == "H" {
				size = size + 2
			} else if p.Format[i] == "I" {
				size = size + 4
			} else if strings.Contains(p.Format[i], "s") {
				num, _ := strconv.Atoi(strings.TrimRight(p.Format[i], "s"))
				size = size + num
			}
		}
	}
	return size
}

//整形转换成字节
func IntToBytes(n int) []byte {
	m := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, m)

	gbyte := bytesBuffer.Bytes()

	return gbyte
}

//整形转换成字节4位
func IntToBytes4(n int) []byte {
	m := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, m)

	return bytesBuffer.Bytes()
}

//整形转换成字节2位
func IntToBytes2(n int) []byte {
	m := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})

	binary.Write(bytesBuffer, binary.BigEndian, m)

	return bytesBuffer.Bytes()
}

//字节转换成整形
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.LittleEndian, &x)

	return int(x)
}

//4个字节转换成整形
func Bytes4ToInt(b []byte) int {
	xx := make([]byte, 4)
	if len(b) == 2 {
		xx = []byte{b[0], b[1], 0, 0}
	} else {
		xx = b
	}

	m := len(xx)
	nb := make([]byte, 4)
	for i := 0; i < 4; i++ {
		nb[i] = xx[m-i-1]
	}
	bytesBuffer := bytes.NewBuffer(nb)

	var x int32
	binary.Read(bytesBuffer, binary.LittleEndian, &x)

	return int(x)
}

func BytesCombine(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

const (
	// JDWP protocol variables
	HANDSHAKE           = "JDWP-Handshake"
	REQUEST_PACKET_TYPE = 0x00
	REPLY_PACKET_TYPE   = 0x80
	//Other codes
	MODKIND_COUNT          = 1
	MODKIND_THREADONLY     = 2
	MODKIND_CLASSMATCH     = 5
	MODKIND_LOCATIONONLY   = 7
	EVENT_BREAKPOINT       = 2
	SUSPEND_EVENTTHREAD    = 1
	SUSPEND_ALL            = 2
	NOT_IMPLEMENTED        = 99
	VM_DEAD                = 112
	INVOKE_SINGLE_THREADED = 2
	TAG_OBJECT             = 76
	TAG_STRING             = 115
	TYPE_CLASS             = 1
)

var (
	// Command signatures
	VERSION_SIG            = []int{1, 1}
	CLASSESBYSIGNATURE_SIG = []int{1, 2}
	ALLCLASSES_SIG         = []int{1, 3}
	ALLTHREADS_SIG         = []int{1, 4}
	IDSIZES_SIG            = []int{1, 7}
	CREATESTRING_SIG       = []int{1, 11}
	SUSPENDVM_SIG          = []int{1, 8}
	RESUMEVM_SIG           = []int{1, 9}
	SIGNATURE_SIG          = []int{2, 1}
	FIELDS_SIG             = []int{2, 4}
	METHODS_SIG            = []int{2, 5}
	GETVALUES_SIG          = []int{2, 6}
	CLASSOBJECT_SIG        = []int{2, 11}
	INVOKESTATICMETHOD_SIG = []int{3, 3}
	REFERENCETYPE_SIG      = []int{9, 1}
	INVOKEMETHOD_SIG       = []int{9, 6}
	STRINGVALUE_SIG        = []int{10, 1}
	THREADNAME_SIG         = []int{11, 1}
	THREADSUSPEND_SIG      = []int{11, 2}
	THREADRESUME_SIG       = []int{11, 3}
	THREADSTATUS_SIG       = []int{11, 4}
	EVENTSET_SIG           = []int{15, 1}
	EVENTCLEAR_SIG         = []int{15, 2}
	EVENTCLEARALL_SIG      = []int{15, 3}
)

type JDWPClient struct {
	Id     int
	Host   string
	Port   int
	socket *net.TCPConn
	debug  bool

	fieldIDSize         int
	objectIDSize        int
	referenceTypeIDSize int
	methodIDSize        int
	frameIDSize         int
	description         string
	jdwpMajor           int
	jdwpMinor           int
	vmVersion           string
	vmName              string
}

func NewJDWPClient(host string, port int) *JDWPClient {
	if port == 0 {
		port = 8000
	}
	return &JDWPClient{
		Id:    0x01,
		Host:  host,
		Port:  port,
		debug: false,
	}
}

func (this *JDWPClient) SetDebug(debug bool) {
	this.debug = debug
}

func (this JDWPClient) log(format string, data ...interface{}) {
	if this.debug {
		log.Printf(format, data)
	}
}

func (this *JDWPClient) GetVMInfo() string {
	return fmt.Sprintf("%s-%s", this.vmName, this.vmVersion)
}

func (this *JDWPClient) Start() {
	err := this.handshake()
	if err != nil {
		return
	}
	this.idsizes()
	this.getversion()
}

func (this *JDWPClient) Leave() {
	if this.socket != nil {
		this.socket.Close()
	}
}

func (this *JDWPClient) handshake() error {
	addr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", this.Host, this.Port))
	if err != nil {
		this.log("解析目标地址失败, 原因:%s \n", err.Error())
		return err
	}
	socket, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		this.log("连接出错, 原因:%s\n", err.Error())
		return err
	}
	socket.Write([]byte(HANDSHAKE))
	data := make([]byte, len(HANDSHAKE))
	socket.SetReadDeadline(time.Now().Add(time.Second * 5))
	n, err := socket.Read(data)
	if err != nil {
		this.log("[handshake] 读取数据出错,原因: %s\n", err.Error())
		return err
	}
	if string(data[:len(HANDSHAKE)]) != HANDSHAKE {
		return errors.New(fmt.Sprintf("握手失败, %s\n", data[:n]))
	}
	this.socket = socket
	return nil
}
func (this *JDWPClient) getversion() {
	m, err := this.socket.Write(this.create_packet(VERSION_SIG, ""))
	if err != nil {
		log.Println(err.Error())
	}
	this.log("[getversion] Send %d bytes\n", m)
	data := []byte{}
	data, err = this.read_reply()
	if err != nil {
		this.log("[getversion] 读取数据出错, 原因:%s\n", err.Error())
		return
	}

	formats := [][]interface{}{
		[]interface{}{"S", "description"},
		[]interface{}{"I", "jdwpMajor"},
		[]interface{}{"I", "jdwpMinor"},
		[]interface{}{"S", "vmVersion"},
		[]interface{}{"S", "vmName"},
	}

	for _, entry := range this.parse_entries(data, formats, false) {
		for name, value := range entry {
			this.setattr(name, value)
		}
	}
}
func (this *JDWPClient) idsizes() {
	idpkt := this.create_packet(IDSIZES_SIG, "")
	m, err := this.socket.Write(idpkt)
	if err != nil {
		log.Println(err.Error())
	}
	this.log("[idsizes] Send: %d bytes\n", m)
	data := []byte{}
	data, err = this.read_reply()
	if err != nil {
		this.log("[idsizes] 读取数据出错, 原因:%s\n", err.Error())
		return
	}
	formats := [][]interface{}{
		[]interface{}{"I", "fieldIDSize"},
		[]interface{}{"I", "methodIDSize"},
		[]interface{}{"I", "objectIDSize"},
		[]interface{}{"I", "referenceTypeIDSize"},
		[]interface{}{"I", "frameIDSize"},
	}

	for _, entry := range this.parse_entries(data, formats, false) {
		for name, value := range entry {
			this.setattr(name, value)
		}
	}
}

func (this *JDWPClient) setattr(name string, value interface{}) {
	var u interface{}
	u = this
	v := reflect.ValueOf(u)
	if v.Kind() == reflect.Ptr {
		elem := v.Elem()
		field := elem.FieldByName(name)
		switch field.Kind() {
		case reflect.String:
			*(*string)(unsafe.Pointer(field.Addr().Pointer())) = value.(string)
			break
		case reflect.Int:
			*(*int)(unsafe.Pointer(field.Addr().Pointer())) = value.(int)
			break
		default:
			break
		}
	}
}

func (this *JDWPClient) create_packet(cmdsig []int, data string) []byte {
	flags := 0x00
	cmdset := cmdsig[0]
	cmd := cmdsig[1]
	pktlen := len(data) + 11
	p := new(Protocol)
	p.Format = []string{"I", "I", "c", "c", "c"}
	h_byte := p.Pack(pktlen, this.Id, byte(flags), byte(cmdset), byte(cmd))
	return BytesCombine(h_byte, []byte(data))
}

func (this *JDWPClient) read_reply() ([]byte, error) {
	this.socket.SetReadDeadline(time.Now().Add(time.Second * 5))
	header := make([]byte, 11)
	_, err := this.socket.Read(header)
	if err != nil {
		return nil, err
	}
	p := new(Protocol)
	p.Format = []string{"I", "I", "c", "H"}
	headerarr := p.UnPack(header)
	pktlen := headerarr[0].(int)
	// id := headerarr[1].(int)
	flags := headerarr[2].(byte)
	errorcode := headerarr[3].(int)
	if flags == REPLY_PACKET_TYPE {
		if errorcode > 0 {
			return nil, errors.New(fmt.Sprintf("Received errcode %d", errorcode))
		}
	}
	buf := new(bytes.Buffer)
	for buf.Len()+11 < pktlen {
		data := make([]byte, 1024)
		n, err := this.socket.Read(data)
		if err != nil {
			break
		}
		binary.Write(buf, binary.BigEndian, data[:n])
	}
	return buf.Bytes(), nil
}
func (this *JDWPClient) parse_entries(buf []byte, formats [][]interface{}, explicit bool) []map[string]interface{} {
	var nb_entries int
	index := 0
	p := new(Protocol)
	if explicit {
		p.Format = []string{"I"}
		nb_entries = p.UnPack(buf[:4])[0].(int)
	} else {
		nb_entries = 1
	}
	entries := []map[string]interface{}{}
	for i := 0; i < nb_entries; i++ {
		data := make(map[string]interface{})
		for _, format := range formats {
			dfmt := format[0]
			sfmt := ""
			ifmt := 0
			if fmt.Sprintf("%T", dfmt) == "string" {
				sfmt = dfmt.(string)
			}
			if fmt.Sprintf("%T", dfmt) == "int" {
				ifmt = dfmt.(int)
			}
			name := format[1].(string)
			if sfmt == "L" || ifmt == 8 {
				p.Format = []string{"Q"}
				data[name] = p.UnPack(buf[index : index+8])[0].(int)
				index += 8
			} else if sfmt == "I" || ifmt == 4 {
				p.Format = []string{"I"}
				data[name] = p.UnPack(buf[index : index+4])[0].(int)
				index += 4
			} else if sfmt == "S" {
				p.Format = []string{"I"}
				l := p.UnPack(buf[index : index+4])[0].(int)
				data[name] = string(buf[index+4 : index+4+l])
				index += 4 + l
			} else if sfmt == "C" {
				p.Format = []string{"c"}
				data[name] = int(p.UnPack([]byte{buf[index]})[0].(byte))
			} else if sfmt == "Z" {

			}

		}
		entries = append(entries, data)
	}
	return entries
}
