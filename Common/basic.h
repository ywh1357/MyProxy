#pragma once
#ifndef MYPROXY_BASIC
#define MYPROXY_BASIC

#include "iohelper.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <tuple>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <utility>
#include <mutex>
#include <shared_mutex>
#include <spdlog/spdlog.h>

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

	class SessionPackage: public Package {
		friend IoHelper& operator<<(IoHelper&& io, const SessionPackage& package);
		friend IoHelper& operator>>(IoHelper&& io, SessionPackage& package);
	public:
		SessionId sessionId;
		DataVec data;
		explicit SessionPackage(const SessionPackage& other) = default;
		explicit SessionPackage(SessionPackage&& other) = default;
		SessionPackage():Package(Type::Session){}
		SessionPackage(SessionId id) :Package(Type::Session),sessionId(id) {}
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
		TunnelPackage(const TunnelMethod &method) :Package(Type::Tunnel),method(method) {}
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
		NewSessionRequest() :TunnelPackage(TunnelMethod::NewSession){}
		NewSessionRequest(const SessionId& id, const ProtoType& protoType, const AddrType& addrType, DataVec&& host, const uint16_t& port) :
			TunnelPackage(TunnelMethod::NewSession), id(id), protoType(protoType), addrType(addrType), host(std::forward<DataVec>(host)), port(port){}
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
		SessionDestoryNotify(SessionId id) :TunnelPackage(TunnelMethod::SessionDestroy),id(id) {}
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

	class BasicProxySession;

	class SessionManager {
		friend class BasicProxyTunnel;
	public:
		std::shared_ptr<BasicProxySession> get(SessionId id);
		bool insertAndStart(std::shared_ptr<BasicProxySession> session);
		bool remove(SessionId id);
		void setNotified(SessionId id);
		bool checkNotified(SessionId id);
	private:
		std::unordered_map<SessionId, std::shared_ptr<BasicProxySession>> m_sessions;
		std::unordered_set<SessionId> destroyeNotiyedSessions;
		std::shared_mutex destroyeNotifiedSessionsMutex;
		std::shared_mutex sessionsMutex;
		static std::shared_ptr<spdlog::logger> logger;
	};

	class BasicProxyTunnel : public std::enable_shared_from_this<BasicProxyTunnel> {
	public:
		using ssl_socket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
		BasicProxyTunnel(boost::asio::io_service &io, boost::asio::ssl::context &ctx, std::string loggerName = "Tunnel");
		virtual ~BasicProxyTunnel();
		virtual void start() = 0;
		std::shared_ptr<BasicProxyTunnel> self() {
			return shared_from_this();
		}
		inline bool ready() {
			return _handshakeFinished.load(); //wrong?
		}
		SessionManager& manager() {
			return m_manager;
		}
		ssl_socket::lowest_layer_type& connection() {
			return m_tunnelConnection.lowest_layer();
		}
		virtual void write(std::shared_ptr<DataVec> dataPtr);
		void sessionDestroyNotify(SessionId id);
	protected:
		virtual void write_impl();
		virtual void handshake() = 0;
		virtual void startProcess();
		virtual void nextRead();
		virtual void handleRead(const boost::system::error_code &ec, size_t bytes,std::shared_ptr<BasicProxyTunnel>) = 0;
		void dispatch(std::shared_ptr<SessionPackage> package);
		boost::asio::streambuf& readbuf() {
			return m_readBuffer;
		}
		boost::asio::io_service& service() {
			return io;
		}
		Logger& logger() {
			return m_logger;
		}
		ssl_socket& socket() {
			return m_tunnelConnection;
		}
		void disconnect();
	public:
		std::function<void()> onReady;
		std::function<void()> onDisconnected;
	protected:
		std::atomic<bool> _running{ true };
		std::atomic<bool> _handshakeFinished{ false };
	private:
		//boost::asio::ip::tcp::endpoint m_serverEndpoint;
		boost::asio::io_service &io;
		ssl_socket m_tunnelConnection;
		boost::asio::strand m_writeStrand;
		//boost::asio::strand m_readStrand; //not needed
		std::queue<std::shared_ptr<DataVec>> m_writeQueue;
		boost::asio::streambuf m_readBuffer;
		SessionManager m_manager;
		Logger m_logger;
	};

	class BasicProxySession {
	public:
		BasicProxySession(SessionId id, boost::asio::io_service &io, std::string loggerName = "Session") :
			m_id(id), io(io) {
			m_logger = spdlog::get(loggerName);
			if (!m_logger) {
				m_logger = spdlog::stdout_color_mt(loggerName);
			}
		}
		virtual ~BasicProxySession() {
			//std::cout << "~BasicProxySession\n";
		}
		SessionId id() const {
			return m_id;
		}
		virtual void start() = 0;
		virtual void stop() = 0;
		virtual void setTunnel(std::shared_ptr<BasicProxyTunnel> tunnel) { 
			if (!tunnel) {
				throw std::runtime_error("BasicProxySession::setTunnel(): parameter: tunnel(std::shared_ptr<BasicProxyTunnel>) unavailable");
			}
			this->_tunnel = tunnel; 
		}
		//virtual void newPackage(std::shared_ptr<SessionPackage> package) = 0;
		std::function<void(std::shared_ptr<SessionPackage>)> onReceived = [](std::shared_ptr<SessionPackage>) {};
	protected:
		boost::asio::io_service& service() {
			return io;
		}
		std::shared_ptr<BasicProxyTunnel> tunnel() { return _tunnel; }
		Logger logger() {
			return m_logger;
		}
	private:
		boost::asio::io_service &io;
		const SessionId m_id;
		std::shared_ptr<BasicProxyTunnel> _tunnel;
		Logger m_logger;
	};


	template <typename T>
	void unused(const T&) {

	}
}


#endif // !MyProxyBasic
