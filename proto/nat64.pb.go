// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proto/nat64.proto

package proto

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type NAT64 struct {
	Account              uint32   `protobuf:"varint,1,opt,name=account,proto3" json:"account,omitempty"`
	Id                   string   `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	Eipv4                string   `protobuf:"bytes,3,opt,name=eipv4,proto3" json:"eipv4,omitempty"`
	Eipv6                string   `protobuf:"bytes,4,opt,name=eipv6,proto3" json:"eipv6,omitempty"`
	Enabled              bool     `protobuf:"varint,5,opt,name=enabled,proto3" json:"enabled,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NAT64) Reset()         { *m = NAT64{} }
func (m *NAT64) String() string { return proto.CompactTextString(m) }
func (*NAT64) ProtoMessage()    {}
func (*NAT64) Descriptor() ([]byte, []int) {
	return fileDescriptor_e958308139f5cca9, []int{0}
}

func (m *NAT64) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NAT64.Unmarshal(m, b)
}
func (m *NAT64) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NAT64.Marshal(b, m, deterministic)
}
func (m *NAT64) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NAT64.Merge(m, src)
}
func (m *NAT64) XXX_Size() int {
	return xxx_messageInfo_NAT64.Size(m)
}
func (m *NAT64) XXX_DiscardUnknown() {
	xxx_messageInfo_NAT64.DiscardUnknown(m)
}

var xxx_messageInfo_NAT64 proto.InternalMessageInfo

func (m *NAT64) GetAccount() uint32 {
	if m != nil {
		return m.Account
	}
	return 0
}

func (m *NAT64) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *NAT64) GetEipv4() string {
	if m != nil {
		return m.Eipv4
	}
	return ""
}

func (m *NAT64) GetEipv6() string {
	if m != nil {
		return m.Eipv6
	}
	return ""
}

func (m *NAT64) GetEnabled() bool {
	if m != nil {
		return m.Enabled
	}
	return false
}

type GetNAT64Request struct {
	Ids                  []string `protobuf:"bytes,1,rep,name=ids,proto3" json:"ids,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetNAT64Request) Reset()         { *m = GetNAT64Request{} }
func (m *GetNAT64Request) String() string { return proto.CompactTextString(m) }
func (*GetNAT64Request) ProtoMessage()    {}
func (*GetNAT64Request) Descriptor() ([]byte, []int) {
	return fileDescriptor_e958308139f5cca9, []int{1}
}

func (m *GetNAT64Request) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetNAT64Request.Unmarshal(m, b)
}
func (m *GetNAT64Request) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetNAT64Request.Marshal(b, m, deterministic)
}
func (m *GetNAT64Request) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetNAT64Request.Merge(m, src)
}
func (m *GetNAT64Request) XXX_Size() int {
	return xxx_messageInfo_GetNAT64Request.Size(m)
}
func (m *GetNAT64Request) XXX_DiscardUnknown() {
	xxx_messageInfo_GetNAT64Request.DiscardUnknown(m)
}

var xxx_messageInfo_GetNAT64Request proto.InternalMessageInfo

func (m *GetNAT64Request) GetIds() []string {
	if m != nil {
		return m.Ids
	}
	return nil
}

type GetNAT64Response struct {
	Retcode              int32             `protobuf:"varint,1,opt,name=retcode,proto3" json:"retcode,omitempty"`
	Message              string            `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	Nat64S               map[string]*NAT64 `protobuf:"bytes,3,rep,name=nat64s,proto3" json:"nat64s,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *GetNAT64Response) Reset()         { *m = GetNAT64Response{} }
func (m *GetNAT64Response) String() string { return proto.CompactTextString(m) }
func (*GetNAT64Response) ProtoMessage()    {}
func (*GetNAT64Response) Descriptor() ([]byte, []int) {
	return fileDescriptor_e958308139f5cca9, []int{2}
}

func (m *GetNAT64Response) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetNAT64Response.Unmarshal(m, b)
}
func (m *GetNAT64Response) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetNAT64Response.Marshal(b, m, deterministic)
}
func (m *GetNAT64Response) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetNAT64Response.Merge(m, src)
}
func (m *GetNAT64Response) XXX_Size() int {
	return xxx_messageInfo_GetNAT64Response.Size(m)
}
func (m *GetNAT64Response) XXX_DiscardUnknown() {
	xxx_messageInfo_GetNAT64Response.DiscardUnknown(m)
}

var xxx_messageInfo_GetNAT64Response proto.InternalMessageInfo

func (m *GetNAT64Response) GetRetcode() int32 {
	if m != nil {
		return m.Retcode
	}
	return 0
}

func (m *GetNAT64Response) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *GetNAT64Response) GetNat64S() map[string]*NAT64 {
	if m != nil {
		return m.Nat64S
	}
	return nil
}

func init() {
	proto.RegisterType((*NAT64)(nil), "uver.NAT64")
	proto.RegisterType((*GetNAT64Request)(nil), "uver.GetNAT64Request")
	proto.RegisterType((*GetNAT64Response)(nil), "uver.GetNAT64Response")
	proto.RegisterMapType((map[string]*NAT64)(nil), "uver.GetNAT64Response.Nat64sEntry")
}

func init() { proto.RegisterFile("proto/nat64.proto", fileDescriptor_e958308139f5cca9) }

var fileDescriptor_e958308139f5cca9 = []byte{
	// 299 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x51, 0x41, 0x4f, 0xb3, 0x40,
	0x14, 0xcc, 0x42, 0xe9, 0x57, 0x1e, 0x9f, 0x5a, 0x37, 0x6a, 0x36, 0x3d, 0x21, 0x5e, 0x38, 0x61,
	0x82, 0x84, 0x68, 0x6f, 0x1e, 0xd4, 0x78, 0xe9, 0x61, 0xf5, 0x0f, 0x50, 0x78, 0x31, 0xc4, 0x0a,
	0xc8, 0x2e, 0x98, 0xfe, 0x45, 0x7f, 0x95, 0xd9, 0xdd, 0x6e, 0x6a, 0x1a, 0x6f, 0x33, 0xf3, 0x1e,
	0x33, 0xf3, 0x58, 0x38, 0xed, 0xfa, 0x56, 0xb6, 0xd7, 0x4d, 0x21, 0xf3, 0x2c, 0xd1, 0x98, 0x4e,
	0x86, 0x11, 0xfb, 0xe8, 0x0b, 0xbc, 0xd5, 0xfd, 0x6b, 0x9e, 0x51, 0x06, 0xff, 0x8a, 0xb2, 0x6c,
	0x87, 0x46, 0x32, 0x12, 0x92, 0xf8, 0x88, 0x5b, 0x4a, 0x8f, 0xc1, 0xa9, 0x2b, 0xe6, 0x84, 0x24,
	0xf6, 0xb9, 0x53, 0x57, 0xf4, 0x0c, 0x3c, 0xac, 0xbb, 0x31, 0x63, 0xae, 0x96, 0x0c, 0xb1, 0x6a,
	0xce, 0x26, 0x7b, 0x35, 0x57, 0xae, 0xd8, 0x14, 0xeb, 0x0d, 0x56, 0xcc, 0x0b, 0x49, 0x3c, 0xe3,
	0x96, 0x46, 0x57, 0x70, 0xf2, 0x84, 0x52, 0x67, 0x73, 0xfc, 0x1c, 0x50, 0x48, 0x3a, 0x07, 0xb7,
	0xae, 0x04, 0x23, 0xa1, 0x1b, 0xfb, 0x5c, 0xc1, 0xe8, 0x9b, 0xc0, 0x7c, 0xbf, 0x25, 0xba, 0xb6,
	0x11, 0xa8, 0x3c, 0x7b, 0x94, 0x65, 0x5b, 0xa1, 0x6e, 0xea, 0x71, 0x4b, 0xd5, 0xe4, 0x03, 0x85,
	0x28, 0xde, 0x70, 0x57, 0xd7, 0x52, 0xba, 0x84, 0xa9, 0xbe, 0x5d, 0x30, 0x37, 0x74, 0xe3, 0x20,
	0x8d, 0x12, 0x75, 0x7d, 0x72, 0xe8, 0x9d, 0xac, 0xf4, 0xd2, 0x43, 0x23, 0xfb, 0x2d, 0xdf, 0x7d,
	0xb1, 0x78, 0x84, 0xe0, 0x97, 0xac, 0x5a, 0xbe, 0xe3, 0x56, 0x47, 0xfb, 0x5c, 0x41, 0x7a, 0x09,
	0xde, 0x58, 0x6c, 0x06, 0x13, 0x1a, 0xa4, 0x81, 0xf1, 0x36, 0xc6, 0x66, 0xb2, 0x74, 0x6e, 0x49,
	0xfa, 0x0c, 0xff, 0xb5, 0xf6, 0x82, 0xfd, 0x58, 0x97, 0x48, 0xef, 0x60, 0x66, 0xf3, 0xe9, 0xf9,
	0x61, 0x1f, 0xfd, 0x47, 0x16, 0x17, 0x7f, 0xd7, 0x5c, 0x4f, 0xf5, 0x13, 0xde, 0xfc, 0x04, 0x00,
	0x00, 0xff, 0xff, 0x3a, 0x3e, 0xfc, 0xbd, 0xd7, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// NAT64ServiceClient is the client API for NAT64Service service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type NAT64ServiceClient interface {
	GetNAT64(ctx context.Context, in *GetNAT64Request, opts ...grpc.CallOption) (*GetNAT64Response, error)
}

type nAT64ServiceClient struct {
	cc *grpc.ClientConn
}

func NewNAT64ServiceClient(cc *grpc.ClientConn) NAT64ServiceClient {
	return &nAT64ServiceClient{cc}
}

func (c *nAT64ServiceClient) GetNAT64(ctx context.Context, in *GetNAT64Request, opts ...grpc.CallOption) (*GetNAT64Response, error) {
	out := new(GetNAT64Response)
	err := c.cc.Invoke(ctx, "/uver.NAT64Service/GetNAT64", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NAT64ServiceServer is the server API for NAT64Service service.
type NAT64ServiceServer interface {
	GetNAT64(context.Context, *GetNAT64Request) (*GetNAT64Response, error)
}

func RegisterNAT64ServiceServer(s *grpc.Server, srv NAT64ServiceServer) {
	s.RegisterService(&_NAT64Service_serviceDesc, srv)
}

func _NAT64Service_GetNAT64_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetNAT64Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NAT64ServiceServer).GetNAT64(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/uver.NAT64Service/GetNAT64",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NAT64ServiceServer).GetNAT64(ctx, req.(*GetNAT64Request))
	}
	return interceptor(ctx, in, info, handler)
}

var _NAT64Service_serviceDesc = grpc.ServiceDesc{
	ServiceName: "uver.NAT64Service",
	HandlerType: (*NAT64ServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetNAT64",
			Handler:    _NAT64Service_GetNAT64_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/nat64.proto",
}