#pragma once
#ifndef MYPROXY_PACKAGES
#define MYPROXY_PACKAGES

#include "define.h"
#include "iohelper.h"

namespace MyProxy {

	class Package {
		friend IoHelper& operator<<(IoHelper&& io, const Package& package);
		friend IoHelper& operator>>(IoHelper&& io, Package& package);
	public:
		enum Type : uint8_t { Unknow, Tunnel, Session };
		using SizeType = uint32_t;
		Type type;
		explicit Package(const Package& other) = default;
		explicit Package(Package&& other) = default;
		Package(Type type = Type::Unknow) :type(type) {}
		virtual SizeType size() const {
			return sizeof(Type) + sizeof(SizeType);
		}
		virtual DataVec toDataVec() const {
			DataVec vec;
			vec.reserve(size());
			IoHelper(vec).putCastedValues<uint8_t, SizeType>(type, size());
			return vec;
		}
		static size_t remainBytes(const char* buf, size_t bytes, bool convert = false) {
			if (bytes < sizeof(Type) + sizeof(SizeType)) {
				return sizeof(Type) + sizeof(SizeType) - bytes;
			}
			SizeType packageSize = *reinterpret_cast<const SizeType*>(buf + 1);
			if (convert) {
				boost::endian::big_to_native(packageSize);
			}
			size_t remianbytes = packageSize - bytes;
			return remianbytes;
		}
	};

	//IoHelper& operator<<(IoHelper&& io, const Package& package);
	//IoHelper& operator>>(IoHelper&& io, Package& package);

	class SessionPackage : public Package {
		friend IoHelper& operator<<(IoHelper&& io, const SessionPackage& package);
		friend IoHelper& operator>>(IoHelper&& io, SessionPackage& package);
	public:
		SessionId sessionId;
		DataVec data;
		explicit SessionPackage(const SessionPackage& other) = default;
		explicit SessionPackage(SessionPackage&& other) = default;
		SessionPackage() :Package(Type::Session) {}
		SessionPackage(SessionId id) :Package(Type::Session), sessionId(id) {}
		SessionPackage(SessionId id, const DataVec& data) :Package(Type::Session), sessionId(id), data(data) {}
		SessionPackage(SessionId id, DataVec&& data) :Package(Type::Session), sessionId(id), data(data) {}
		virtual SizeType size() const override {
			return (SizeType)(Package::size() + sizeof(sessionId) + data.size());
		}
		SizeType calcDataSize(SizeType size) {
			return (SizeType)(size - Package::size() - sizeof(sessionId));
		}
		virtual DataVec toDataVec() const override {
			auto size = this->size();
			DataVec vec;
			vec.reserve(size);
			IoHelper(vec).putCastedValues<uint8_t, Package::SizeType, SessionId, DataVec>
				(type, size, sessionId, data);
			return vec;
		}
	};

	class TunnelPackage : public Package {
	public:
		TunnelMethod method;
		TunnelPackage() :Package(Type::Tunnel) {}
		TunnelPackage(const TunnelMethod &method) :Package(Type::Tunnel), method(method) {}
		static TunnelMethod getTunnelMethod(const char* buf) {
			return *reinterpret_cast<const TunnelMethod*>(buf + sizeof(Type) + sizeof(SizeType));
		}
		virtual SizeType size() const override {
			return (SizeType)(Package::size() + sizeof(TunnelMethod));
		}
	};

	class NewSessionRequest : public TunnelPackage {
		friend IoHelper& operator<<(IoHelper&& io, const NewSessionRequest& package);
		friend IoHelper& operator>>(IoHelper&& io, NewSessionRequest& package);
	public:
		SessionId id;
		ProtoType protoType;
		AddrType addrType;
		DataVec host;
		uint16_t port;
		NewSessionRequest() :TunnelPackage(TunnelMethod::NewSession) {}
		NewSessionRequest(const SessionId& id, const ProtoType& protoType, const AddrType& addrType, DataVec&& host, const uint16_t& port) :
			TunnelPackage(TunnelMethod::NewSession), id(id), protoType(protoType), addrType(addrType), host(std::forward<DataVec>(host)), port(port) {}
		virtual SizeType size() const override {
			return (SizeType)(exceptHostSize() + host.size());
		}
		SizeType calcHostSize(SizeType size) const {
			return size - exceptHostSize();
		}
		virtual DataVec toDataVec() const override {
			auto size = this->size();
			DataVec vec;
			vec.reserve(size);
			IoHelper(vec).putCastedValues<uint8_t, Package::SizeType, uint8_t, SessionId, uint8_t, uint8_t, DataVec, uint16_t>
				(type, size, method, id, protoType, addrType, host, port);
			return vec;
		}
	private:
		SizeType exceptHostSize() const {
			return (SizeType)(TunnelPackage::size() + sizeof(SessionId) + sizeof(ProtoType) + sizeof(AddrType) + sizeof(uint16_t));
		}
	};

	class SessionDestoryNotify : public TunnelPackage {
		friend IoHelper& operator>>(IoHelper& io, SessionDestoryNotify& package);
	public:
		SessionId id;
		SessionDestoryNotify() :TunnelPackage(TunnelMethod::SessionDestroy) {}
		SessionDestoryNotify(SessionId id) :TunnelPackage(TunnelMethod::SessionDestroy), id(id) {}
		virtual SizeType size() const override {
			return (SizeType)(TunnelPackage::size() + sizeof(SessionId));
		}
		virtual DataVec toDataVec() const override {
			DataVec vec;
			vec.reserve(size());
			IoHelper(vec).putCastedValues<uint8_t, Package::SizeType, uint8_t, SessionId>
				(type, size(), method, id);
			return vec;
		}
	};
}


#endif // !MYPROXY_PACKAGES

