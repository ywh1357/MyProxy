#pragma once
#include "basic.h"
#include "abstractproxysession.h"

namespace MyProxy {

	namespace Server {

		class ServerProxyTunnel : public BasicProxyTunnel {
		public:
			ServerProxyTunnel(boost::asio::io_service &io, boost::asio::ssl::context &ctx) :BasicProxyTunnel(io, ctx, "ServerProxyTunnel") {
			}
			~ServerProxyTunnel() {
				//logger()->debug("destroyed");
			}
			virtual void start() override {
				logger()->debug("Server Tunnel start handshake");
				handshake();
			}
			virtual void handshake() override;
		protected:
			virtual void handleRead(const boost::system::error_code &ec, size_t bytes, std::shared_ptr<BasicProxyTunnel>) override;
		};

		template <typename Protocol>
		class ServerProxySession : public AbstractProxySession<Protocol> {
			using Base = AbstractProxySession<Protocol>;
			using TraitsType = ServerProxySession<Protocol>;
		public:
			ServerProxySession(SessionId id, boost::asio::io_service &io, AddrType addrType,const DataVec& destHost,const uint16_t& destPort)
				:AbstractProxySession<Protocol>(id, io, "ServerSession"), _resolver(io),
				_addrType(addrType), _destHost(destHost), _destPort(destPort) {
				++ServerProxySession<Protocol>::count;
			}
			ServerProxySession(SessionId id, boost::asio::io_service &io, AddrType addrType, DataVec&& destHost, const uint16_t& destPort)
				:AbstractProxySession<Protocol>(id, io,"ServerSession"), _resolver(io),
				_addrType(addrType), _destHost(std::move(destHost)), _destPort(destPort) {
				++ServerProxySession<Protocol>::count;
			}
			ServerProxySession(const NewSessionRequest &request, boost::asio::io_service &io):
				AbstractProxySession<Protocol>(request.id, io, "ServerSession"), _resolver(io),
				_addrType(request.addrType), _destHost(request.host), _destPort(request.port) {
				++ServerProxySession<Protocol>::count;
			}
			ServerProxySession(NewSessionRequest &&request, boost::asio::io_service &io) :
				AbstractProxySession<Protocol>(request.id, io, "ServerSession"), _resolver(io),
				_addrType(request.addrType), _destHost(std::move(request.host)), _destPort(request.port) {
				++ServerProxySession<Protocol>::count;
			}
			virtual ~ServerProxySession() {
				this->logger()->debug("Session ID: {} destroyed. last: {}", this->id(), --ServerProxySession<Protocol>::count);
			}
			virtual void start() override { 
				this->handshakeDest();
			};
		private:
			static size_t count;
			//void handshakeTunnel(std::shared_ptr<SessionPackage> package);
			void handshakeDest();
			void statusNotify(State state);
		private:
			State _state;
			AddrType _addrType;
			DataVec _destHost;
			uint16_t _destPort;
			typename Protocol::resolver _resolver;
		};

		template <typename Protocol>
		size_t ServerProxySession<Protocol>::count = 0;

		template<typename Protocol>
		inline void ServerProxySession<Protocol>::handshakeDest()
		{
			using namespace boost::asio;
			std::string hostStr(_destHost.data(), _destHost.size());
			auto query = std::make_shared<typename Protocol::resolver::query>(hostStr, std::to_string(_destPort));
			_resolver.async_resolve(*query, 
				[this, query, hostStr = std::move(hostStr), self = this->shared_from_this()]
				(const boost::system::error_code &ec, typename Protocol::resolver::iterator it) {
				if (ec) {
					if (ec == boost::asio::error::operation_aborted)
						return;
					this->logger()->warn("ID: {} Resolve {}:{} failed: {}", this->id(), hostStr, _destPort, ec.message());
					this->statusNotify(State::Failure);
					this->destroy();
					return;
				}
				async_connect(this->socket(), it, [this, hostStr = std::move(hostStr), self]
					(const boost::system::error_code &ec, typename Protocol::resolver::iterator it) {
					if (ec) {
						if (ec == boost::asio::error::operation_aborted)
							return;
						this->logger()->warn("ID: {} Connect to destination: {}:{} failed: {}", this->id(), hostStr, _destPort, ec.message());
						this->statusNotify(State::Failure);
						this->destroy();
						return;
					}
					auto ep = (*it).endpoint();
					this->logger()->debug("ID: {} Connect to destination: {}:{} succeed",this->id(), ep.address().to_string(), ep.port());
					this->startForwarding();
					this->statusNotify(State::Succeeded);
				});
			});
		}

		template<typename Protocol>
		inline void ServerProxySession<Protocol>::statusNotify(State state)
		{
			SessionPackage package{ this->id(),DataVec{ static_cast<char>(state) } };
			this->tunnel()->write(std::make_shared<DataVec>(package.toDataVec()));
		}

		class Server {
		public:
			Server(boost::asio::io_service &io);
			~Server();
			void setCert(std::string path);
			void setKey(std::string path);
			void bind(std::string port, std::string bindAddress = std::string());
			void start();
		private:
			void startAccept();
		private:
			boost::asio::io_service::work m_work;
			std::shared_ptr<boost::asio::ip::tcp::acceptor> m_tcpAcceptor;
			//std::string m_bindAddress;
			//std::string m_bindPort;
			//SessionId m_maxSessionId = 0;
			std::shared_ptr<ServerProxyTunnel> m_tunnel;
			Logger m_logger = spdlog::stdout_color_mt("Server");
			boost::asio::ssl::context m_ctx{ boost::asio::ssl::context::tlsv12_server };
		};
		
	}
}