#pragma once
#ifndef MYPROXY_LOCAL
#define MYPROXY_LOCAL

#include "basic.h"
#include "abstractproxysession.h"

namespace MyProxy {

	namespace Local {

		std::string parseHost(AddrType type, const DataVec &vec);

		class LocalProxyTunnel : public BasicProxyTunnel {
		public:
			LocalProxyTunnel(boost::asio::io_service &io, boost::asio::ssl::context &ctx):BasicProxyTunnel(io, ctx, "LocalProxyTunnel"){}
			virtual void start() override {
				logger()->debug("Local Tunnel start handshake");
				handshake();
			}
		protected:
			virtual void handshake() override;
			virtual void handleRead(const boost::system::error_code &ec, size_t bytes, std::shared_ptr<BasicProxyTunnel>) override;
		};

		template <typename Protocol>
		class LocalProxySession : public AbstractProxySession<Protocol> {
		public:
			LocalProxySession(SessionId id, boost::asio::io_service &io) :
				AbstractProxySession<Protocol>(id, io, "LocalSession") {
				++LocalProxySession<Protocol>::count;
			}
			virtual ~LocalProxySession() {
				logger()->debug("Session ID: {} destroyed. last: {}", id(), --LocalProxySession<Protocol>::count);
			}
			virtual void start() override { handshakeLocal(); };
		private:
			void handshakeLocal();
			void handshakeTunnel();
			void handshakeTunnelFinish(std::shared_ptr<SessionPackage> package);
			void handshakeLocalFinish();
			static size_t count;
		private:
			ProtoVer _version;
			ReqType _reqType;
			State _state;
			AddrType _addrType;
			DataVec _destHost;
			uint16_t _destPort;
		};

		template <typename Protocol>
		size_t LocalProxySession<Protocol>::count = 0;

		template <typename Protocol>
		void LocalProxySession<Protocol>::handshakeLocal() {
			using namespace boost::asio;
			auto buf = std::make_shared<streambuf>();
			async_read(this->socket(), *buf, [this, buf](const boost::system::error_code& ec, std::size_t bytes) -> size_t {
				if (ec) {
					return 0;
				}
				if (buf->size() < 3) {
					return (3 - buf->size());
				}
				size_t num = static_cast<size_t>(buffer_cast<const char*>(buf->data())[1]);
				if (buf->size() < num + 2) {
					return (num + 2 - buf->size());
				}
				else {
					return 0;
				}
			},
				[this, buf, self = shared_from_this()](const boost::system::error_code& ec, size_t bytes) {
				if (!ec) {
					IoHelper io(buf.get());
					auto[ver, num] = io.getTuple<ProtoVer, size_t>(_1B, _1B);
					if (ver != ProtoVer::Socket5) {
						logger()->error("Session ID: {} unsupported version: 0x{:x}", id(),static_cast<uint8_t>(ver));
						destroy(); //error unsupport
						return;
					}
					DataVec authMethodList(num);
					io.getValues(authMethodList);
					bool support = false;
					for (const auto& method : authMethodList) {
						if (static_cast<ProtoVer>(method) == AuthType::None) {
							support = true;
							break;
						}
					}
					if (support) {
						std::shared_ptr<DataVec> rsp(new DataVec{ 0x05,0x00 });
						async_write(this->socket(), buffer(*rsp), transfer_all(), [this, rsp](const boost::system::error_code &ec, size_t bytes) {
							if (ec) {
								logger()->error("Session ID: {} response write error: {}", id(),ec.message());
								destroy(); //error
								return;
							}
							handshakeTunnel();
						});
					}
					else {
						logger()->error("Session ID: {} unsupported method",id());
						destroy(); //error unsupport
						return;
					}
				}
				else {
					logger()->error("Session ID: {} handshakeLocal() error", id(), ec.message());
					destroy();
				}
			});
		}

		template<typename Protocol>
		inline void LocalProxySession<Protocol>::handshakeTunnel()
		{
			using namespace boost::asio;
			auto buf = std::make_shared<streambuf>();
			async_read(this->socket(), *buf, [this, buf](const boost::system::error_code& ec, size_t bytes) -> size_t {
				if (ec) {
					return 0;
				}
				if (buf->size() < 4) {
					return 4 - buf->size();
				}
				AddrType at = static_cast<AddrType>(buffer_cast<const char*>(buf->data())[3]);
				switch (at)
				{
				case MyProxy::IPV4:
					return 10 - buf->size();
					break;
				case MyProxy::Domain:
					if (buf->size() < 5)
						return 5 - buf->size();
					else
						return 4 + 1 + static_cast<size_t>(buffer_cast<const char*>(buf->data())[4]) + 2 - buf->size();
					break;
				case MyProxy::IPV6:
					return (4 + 128 + 2 - buf->size());
					break;
				default:
					return 0;
					break;
				}
			}, [this, buf, self = shared_from_this()](const boost::system::error_code& ec, size_t bytes) {
				if (!ec) {
					IoHelper io(buf.get());
					//auto[ver, _reqType, nil, _addrType] = io.getTuple<ProtoVer, ReqType, short, AddrType>(_1B, _1B, _1B, _1B);
					char nil;
					io.getCastedValues<uint8_t, uint8_t, uint8_t, uint8_t>(_version, _reqType, nil, _addrType);
					switch (_reqType)
					{
					case MyProxy::Connect:
						break;
					default:
						logger()->error("Session ID: {} unsupported request type {}", id(), ec.message(), _reqType);
						destroy(); //error unsupport
						return;
						break;
					}
					size_t hostSize;
					switch (_addrType) {
					case MyProxy::AddrType::IPV4:
						hostSize = 4;
						break;
					case MyProxy::AddrType::IPV6:
						hostSize = 16;
						break;
					case MyProxy::AddrType::Domain:
						hostSize = io.getValue<uint8_t>();
						break;
					default:
						logger()->error("Session ID: {} unknown address type {}", id(), ec.message(), _addrType);
						destroy(); //error
						break;
					}
					_destHost.resize(hostSize);
					io.getValues<DataVec>(_destHost);
					std::string hostStr = parseHost(_addrType, _destHost);
					_destPort = io.getValue<uint16_t>();
					boost::endian::big_to_native_inplace(_destPort);
					NewSessionRequest request{ id(), TraitsProtoType<Protocol>::type, _addrType, DataVec{ hostStr.begin(), hostStr.end() }, _destPort };
					tunnel()->write(std::make_shared<DataVec>(request.toDataVec()));
					this->onReceived = std::bind(&LocalProxySession<Protocol>::handshakeTunnelFinish, this, std::placeholders::_1); //need timmer
				}
				else {
					logger()->error("Session ID: {} handshakeTunnel() error {}", id(), ec.message());
					destroy();
				}
			});
		}

		template<typename Protocol>
		inline void LocalProxySession<Protocol>::handshakeTunnelFinish(std::shared_ptr<SessionPackage> package)
		{
			if (package->data.size() != 1)
				_state = State::Failure;
			else
				_state = static_cast<State>(package->data[0]);
			handshakeLocalFinish();
		}

		template<typename Protocol>
		inline void LocalProxySession<Protocol>::handshakeLocalFinish()
		{
			DataVec hostByte;
			if (_addrType == AddrType::Domain) {
				hostByte.push_back(static_cast<char>(_destHost.size()));
			}
			std::copy(_destHost.begin(), _destHost.end(), std::back_inserter(hostByte));
			DataVec buf;
			IoHelper(buf).putCastedValues<uint8_t, uint8_t, uint8_t, uint8_t, DataVec, uint16_t>
				(_version, _state, 0, _addrType, hostByte, boost::endian::native_to_big(_destPort));
			write(std::make_shared<DataVec>(std::move(buf)));
			if (_state == State::Succeeded) {
				startForwarding();
			}
			else {
				logger()->debug("Session ID: {} handshake state failed {}", id(), _state);
				destroy();
			}
		}

		class Local {
		public:
			Local(boost::asio::io_service &io);
			~Local();
			void setServer(std::string host, std::string port);
			void bind(std::string port, std::string bindAddress = std::string());
			void start();
		private:
			void startAccept();
			SessionId newSessionId();
		private:
			boost::asio::io_service::work m_work;
			std::shared_ptr<boost::asio::ip::tcp::acceptor> m_tcpAcceptor;
			std::string m_serverHost;
			std::string m_serverPort;
			SessionId m_maxSessionId = 0;
			std::shared_ptr<LocalProxyTunnel> m_tunnel;
			boost::asio::ip::tcp::resolver m_resolver;
			Logger m_logger = spdlog::stdout_color_mt("Local");
			boost::asio::ssl::context m_ctx{ boost::asio::ssl::context::tls };
			std::shared_mutex tunnelMutex;
			//std::atomic<bool> _tunnelAvailable{ false };
		};

	}

}

#endif // !MYPROXY_LOCAL
