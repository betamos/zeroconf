package zeroconf

import "fmt"

func ExampleNewType() {
	ty := NewType("_chat._tcp")
	fmt.Println(ty)
	// Output: _chat._tcp.local
}

func ExampleNewType_custom() {
	// Provides a custom domain and two subtypes (not recommended)
	ty := NewType("_foo._udp.custom.domain,_sub1,_sub2")
	fmt.Println(ty)
	fmt.Println(ty.Subtypes)

	// Output:
	// _foo._udp.custom.domain
	// [_sub1 _sub2]
}

func ExampleNewService() {
	ty := NewType("_chat._tcp")
	svc := NewService(ty, "bobs-laptop", 12345)
	fmt.Println(svc)

	// Output:
	// bobs-laptop._chat._tcp.local
}
