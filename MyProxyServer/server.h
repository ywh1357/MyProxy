#pragma once
#include "basic.h"
#include "abstractproxysession.h"
#include <chrono>
#include <unordered_map>

namespace MyProxy {

	namespace Server {

		class ResolveCache {
		public:
			template<typename Protocol>
			struct CacheRecord {
				using IteratorType = typename Protocol::resolver::iterator;
				static const IteratorType end;
				IteratorType it;
				std::chrono::time_point<std::chrono::system_clock> expireTime;
				bool expired() {
					return std::chrono::system_clock::now() > expireTime;
				}
				CacheRecord(const IteratorType &it, std::string host, std::string service, std::chrono::duration<int> expire = std::chrono::minutes(10)) :
					it(IteratorType::create(it, IteratorType(), host, service)),
					expireTime(std::chrono::system_clock::now() + expire) {	}
			};
			template<typename Protocol>
			using CacheMapType = typename std::unordered_map<
				typename Protocol::resolver::query,
				typename CacheRecord<Protocol>,
				typename std::function<typename size_t(const typename Protocol::resolver::query&)>,
				typename std::function<typename size_t(const typename Protocol::resolver::query&, const typename Protocol::resolver::query&)>>;
			template <typename Protocol>
			static const typename CacheMapType<Protocol>::iterator Unavailable;
			template<typename Protocol>
			static void cache(const typename Protocol::resolver::query &query, const typename CacheRecord<Protocol>::IteratorType &iter) {
				resolveCache<Protocol>.insert_or_assign(query, iter);
			}
			template<typename Protocol>
			static typename CacheMapType<Protocol>::iterator fetch(const typename Protocol::resolver::query &query) {
				return resolveCache<Protocol>.find(query);
			}
		private:
			template<typename Protocol>
			static bool queryEqualTo(const typename Protocol::resolver::query & l, const typename Protocol::resolver::query & r) {
				return l.host_name() == r.host_name() && l.service_name() == r.service_name();
			}
			template<typename Protocol>
			static size_t queryHasher(const typename Protocol::resolver::query & q) {
				return std::hash <std::string>{}(q.host_name() + ':' + q.service_name());
			}
			static std::shared_mutex resolveCacheMutex;
			template<typename Protocol>
			static CacheMapType<Protocol> resolveCache;
		};

		template<typename Protocol>
		const typename ResolveCache::CacheRecord<Protocol>::IteratorType ResolveCache::CacheRecord<Protocol>::end = typename Protocol::resolver::iterator();

		template <typename Protocol>
		const typename ResolveCache::CacheMapType<Protocol>::iterator ResolveCache::Unavailable = typename ResolveCache::CacheMapType<Protocol>::iterator();

		template<typename Protocol>
		typename ResolveCache::CacheMapType<Protocol> ResolveCache::resolveCache = typename ResolveCache::CacheMapType<Protocol>(0,
			std::bind(&ResolveCache::queryHasher<Protocol>, std::placeholders::_1),
			std::bind(&ResolveCache::queryEqualTo<Protocol>, std::placeholders::_1, std::placeholders::_2)
			);

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
			auto do_connect = [this, self = this->shared_from_this()](typename Protocol::resolver::iterator it, std::string hostStr){
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
					this->logger()->debug("ID: {} Connect to destination: {}:{} succeed", this->id(), ep.address().to_string(), ep.port());
					this->startForwarding();
					this->statusNotify(State::Succeeded);
				});
			};
			std::string hostStr(_destHost.data(), _destHost.size());
			using flags = boost::asio::ip::resolver_query_base::flags;
			auto query = std::make_shared<typename Protocol::resolver::query>
				(hostStr, std::to_string(_destPort), flags::numeric_service | flags::address_configured);
			auto iter = ResolveCache::fetch<Protocol>(*query);
			if (iter != ResolveCache::Unavailable<Protocol> && !iter->second.expired()) {
				do_connect(iter->second.it, std::move(hostStr));
				return;
			}
			else {
				_resolver.async_resolve(*query,
					[this, query, hostStr = std::move(hostStr), do_connect, self = this->shared_from_this()]
				(const boost::system::error_code &ec, typename Protocol::resolver::iterator it) {
					if (ec) {
						if (ec == boost::asio::error::operation_aborted)
							return;
						this->logger()->warn("ID: {} Resolve {}:{} failed: {}", this->id(), hostStr, _destPort, ec.message());
						this->statusNotify(State::Failure);
						this->destroy();
						return;
					}
					this->logger()->debug("ID: {} destination: {}:{} Resolved", this->id(), hostStr, _destPort);
					do_connect(it, std::move(hostStr));
				});
			}
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
			void setCA(std::string path);
			void setCert(std::string path);
			void setKey(std::string path);
			void bind(std::string port, std::string bindAddress = std::string());
			void start();
		private:
			void startAccept();
		private:
			boost::asio::io_service::work m_work;
			std::shared_ptr<boost::asio::ip::tcp::acceptor> m_tcpAcceptor;
			std::shared_ptr<ServerProxyTunnel> m_tunnel;
			Logger m_logger = spdlog::stdout_color_mt("Server");
			boost::asio::ssl::context m_ctx{ boost::asio::ssl::context::tlsv12_server };
		};
	}
}