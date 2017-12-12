#pragma once
#ifndef MYPROXY_DEFINE
#define MYPROXY_DEFINE

#include <vector>
#include <memory>
#include <spdlog/logger.h>

namespace MyProxy {

	using SessionId = uint32_t;
	constexpr static SessionId sessionIdMax = std::numeric_limits<SessionId>::max();
	using Logger = std::shared_ptr<spdlog::logger>;

	enum ProtoVer : uint8_t { Socket5 = 0x05 };
	enum AuthType : uint8_t { None = 0x00, Password = 0x02 };
	enum AddrType : uint8_t { IPV4 = 0x01, Domain = 0x03, IPV6 = 0x04 };
	enum ReqType : uint8_t { Connect = 0x01, Bind = 0x02, UdpAssociate = 0x03 };
	enum State : uint8_t { Succeeded = 0x00, Failure, Refused = 0x05 };
	enum ProtoType : uint8_t { Tcp, Udp };

	enum TunnelMethod : uint8_t { NewSession = 1, SessionDestroy, ReConnect };

}

#endif // MYPROXY_DEFINE
