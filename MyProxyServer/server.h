#pragma once
#include "basic.h"
#include "abstractproxysession.h"
#include "abstractproxytunnel.h"
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <botan/tls_server.h>

namespace MyProxy {

	namespace Server {

		class ResolveCache {
		public:
			template<typename Protocol>
			struct CacheRecord {
				using ResultType = typename Protocol::resolver::results_type;
				//end of the endpoints list
				//static const ResultType end;
				ResultType result;
				std::chrono::time_point<std::chrono::system_clock> expireTime;
				bool expired() {
					return std::chrono::system_clock::now() > expireTime;
				}
				CacheRecord(const ResultType &it, std::chrono::duration<int> expire = std::chrono::minutes(10)) :
					result(it), expireTime(std::chrono::system_clock::now() + expire) {	}
			};
			struct Destination {
				std::string host;
				std::string service;
				Destination(std::string &&_host, std::string && _service) :
					host(std::forward<std::string>(_host)), 
					service(std::forward<std::string>(_service)) {}
			};
			//the std::unordered_map _resolveCache type
			template<typename Protocol>
			using CacheMapType = typename std::unordered_map<
				Destination,
				std::shared_ptr<CacheRecord<Protocol>>,
				std::function<size_t(const Destination&)>,
				std::function<bool(const Destination&, const Destination&)> >;
			//cache record
			template<typename Protocol>
			static void cache(const Destination &dest, const typename CacheRecord<Protocol>::ResultType &result) {
				//write lock
				std::unique_lock<std::shared_mutex> locker(_resolveCacheMutex);
				//insert record or rewrite the expired record
				_resolveCache<Protocol>.insert_or_assign(dest, std::make_shared<CacheRecord<Protocol>>(result));
			}
			//fetch record's shared_ptr, if not found, return invalid shared_ptr
			template<typename Protocol>
			static std::shared_ptr<CacheRecord<Protocol>> fetch(const ResolveCache::Destination &dest) {
				//read lock
				std::shared_lock<std::shared_mutex> locker(_resolveCacheMutex);
				auto iter = _resolveCache<Protocol>.find(dest);
				if (iter != _resolveCache<Protocol>.end())
					return iter->second;
				else
					return std::shared_ptr<CacheRecord<Protocol>>();
			}
		private:
			static bool queryEqualTo(const ResolveCache::Destination & l, const typename ResolveCache::Destination & r) {
				return l.host == r.host && l.service == r.service;
			}
			static size_t queryHasher(const ResolveCache::Destination & q) {
				auto h1 = std::hash<std::string>{}(q.host);
				auto h2 = std::hash<std::string>{}(q.service);
				return h1 ^ (h2 << 1);
			}
			//fetch or cache mutex
			static std::shared_mutex _resolveCacheMutex;
			//data member
			template<typename Protocol>
			static ResolveCache::CacheMapType<Protocol> _resolveCache;
		};

		class ServerProxyTunnel : public AbstractProxyTunnel {
		public:
			ServerProxyTunnel(TLSContext &ctx, boost::asio::io_context & io):
				AbstractProxyTunnel(io, "ServerProxyTunnel"),_ctx(ctx)
			{
			}
			~ServerProxyTunnel() {
				//logger()->debug("destroyed");
			}
			virtual void start() override {
				logger()->debug("Server Tunnel start");
				channel() = std::make_shared<Botan::TLS::Server>
					(*this, *_ctx.session_mgr, *_ctx.creds, *_ctx.policy, *_ctx.rng);
				nextRead();
			}
			virtual bool tls_session_established(const Botan::TLS::Session& session) override;;
		protected:
			virtual void handleRead(std::shared_ptr<DataVec> data) override;
		private:
			TLSContext & _ctx;
		};

		template <typename Protocol>
		class ServerProxySession : public AbstractProxySession<Protocol> {
			using Base = AbstractProxySession<Protocol>;
			using TraitsType = ServerProxySession<Protocol>;
		public:
			ServerProxySession(SessionId id, boost::asio::io_context &io, AddrType addrType,const DataVec& destHost,const uint16_t& destPort)
				:AbstractProxySession<Protocol>(id, io, "ServerSession"), _resolver(io),
				_addrType(addrType), _destHost(destHost), _destPort(destPort) {
				++ServerProxySession<Protocol>::count;
			}
			ServerProxySession(SessionId id, boost::asio::io_context &io, AddrType addrType, DataVec&& destHost, const uint16_t& destPort)
				:AbstractProxySession<Protocol>(id, io,"ServerSession"), _resolver(io),
				_addrType(addrType), _destHost(std::move(destHost)), _destPort(destPort) {
				++ServerProxySession<Protocol>::count;
			}
			ServerProxySession(const NewSessionRequest &request, boost::asio::io_context &io):
				AbstractProxySession<Protocol>(request.id, io, "ServerSession"), _resolver(io),
				_addrType(request.addrType), _destHost(request.host), _destPort(request.port) {
				++ServerProxySession<Protocol>::count;
			}
			ServerProxySession(NewSessionRequest &&request, boost::asio::io_context &io) :
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
			virtual void stop() override {
				Base::stop();
				_resolver.cancel();
			}
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
			//connect method
			auto do_connect = [this, self = this->shared_from_this()](typename Protocol::resolver::results_type result, std::shared_ptr<ResolveCache::Destination> dest){
				async_connect(this->socket(), result, [this, dest, self]
				(const boost::system::error_code &ec, const typename Protocol::endpoint & ep) {
					if (ec) {
						if (ec == boost::asio::error::operation_aborted)
							return;
						this->logger()->warn("ID: {} Connect to destination: {}:{} failed: {}", this->id(), dest->host, dest->service, ec.message());
						this->statusNotify(State::Failure);
						this->destroy(true);
						return;
					}
					this->logger()->debug("ID: {} Connect to destination: {}:{} succeed", this->id(), ep.address().to_string(), ep.port());
					this->startForwarding();
					this->statusNotify(State::Succeeded);
				});
			};
			using flags = boost::asio::ip::resolver_query_base::flags;
			auto dest = std::make_shared<ResolveCache::Destination>(std::string(_destHost.data(), _destHost.size()), std::to_string(_destPort));
			//fetch resolve record's shared_ptr
			auto record = ResolveCache::fetch<Protocol>(*dest);
			//check shared_ptr vaild and expire time
			if (record && !record->expired()) {
				this->logger()->debug("ID: {} destination: {}:{} resolve record fetch succeed.", this->id(), dest->host, dest->service);
				//use cached record
				do_connect(record->result, dest);
				return;
			}
			else {
				//or resolve
				_resolver.async_resolve(dest->host, dest->service,
					[this, dest, do_connect, self = this->shared_from_this()]
				(const boost::system::error_code &ec, typename Protocol::resolver::results_type result) {
					if (ec) {
						if (ec == boost::asio::error::operation_aborted)
							return;
						this->logger()->warn("ID: {} Resolve {}:{} failed: {}", this->id(), dest->host, dest->service, ec.message());
						this->statusNotify(State::Failure);
						this->destroy(true);
						return;
					}
					ResolveCache::cache<Protocol>(*dest, result);
					this->logger()->debug("ID: {} destination: {}:{} resolved, recored cached.", this->id(), dest->host, dest->service);
					do_connect(result, dest);
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
			Server(boost::asio::io_context &io);
			~Server();
			void setCA(std::string path);
			void setCertAndKey(std::string certPath,std::string keyPath);
			void bind(std::string port, std::string bindAddress = std::string());
			void start();
		private:
			void startAccept();
		private:
			boost::asio::io_context &_io;
			boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work;
			std::shared_ptr<boost::asio::ip::tcp::acceptor> m_tcpAcceptor;
			//std::shared_ptr<ServerProxyTunnel> m_tunnel;
			Logger m_logger = spdlog::stdout_color_mt("Server");
			std::unique_ptr<TLSContext> _ctx;
		};
	}
}