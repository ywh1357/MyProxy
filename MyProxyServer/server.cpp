#include "server.h"

using namespace boost::asio;

namespace MyProxy {
	namespace Server {

		std::shared_mutex ResolveCache::_resolveCacheMutex;

		template<typename Protocol>
		const typename ResolveCache::CacheRecord<Protocol>::IteratorType ResolveCache::CacheRecord<Protocol>::end = typename Protocol::resolver::iterator();

		template <typename Protocol>
		const typename ResolveCache::CacheMapType<Protocol>::iterator ResolveCache::invalid = typename ResolveCache::CacheMapType<Protocol>::iterator();

		template<typename Protocol>
		typename ResolveCache::CacheMapType<Protocol> ResolveCache::_resolveCache = typename ResolveCache::CacheMapType<Protocol>(0,
			std::bind(&ResolveCache::queryHasher<Protocol>, std::placeholders::_1),
			std::bind(&ResolveCache::queryEqualTo<Protocol>, std::placeholders::_1, std::placeholders::_2)
			);

		void ServerProxyTunnel::handleRead(std::shared_ptr<DataVec> data)
		{
			if (!_running.load()) {
				logger()->warn("handleRead() cancel: tunnel stoped");
				return;
			}
			auto type = static_cast<Package::Type>(data->at(0));
			if (type == Package::Type::Session) {
				auto package = std::make_shared<SessionPackage>();
				IoHelper(*data) >> *package;
				dispatch(package);
			}
			else if (type == Package::Type::Tunnel) {
				TunnelMethod method = TunnelPackage::getTunnelMethod(data->data());
				if (method == TunnelMethod::NewSession) {
					NewSessionRequest request;
					IoHelper(*data) >> request;
					logger()->debug("NewSessionRequest received ID: {}", request.id);
					std::shared_ptr<BasicProxySession> session;
					if (request.protoType == ProtoType::Tcp) {
						session = std::make_shared<ServerProxySession<ip::tcp>>(std::move(request), service());
					}
					else {
						session = std::make_shared<ServerProxySession<ip::udp>>(std::move(request), service());
					}
					session->setTunnel(shared_from_this());
					manager().insertAndStart(session);
				}
				else if (method == TunnelMethod::SessionDestroy) {
					SessionId sessionId;
					std::tie(std::ignore, std::ignore, std::ignore, sessionId) = IoHelper(*data).getTuple<Package::Type, Package::SizeType, TunnelMethod, SessionId>(_1B, _4B, _1B, _4B);
					auto session = manager().get(sessionId);
					if (session)
						session->destroy(true);
				}
				else {
					logger()->error("Unknown tunnel method");
					disconnect();
					return;
				}
			}
			else {
				//auto header = *buffer_cast<const uint64_t*>(readbuf().data());
				logger()->error("Unknown package received");
				disconnect();
				return;
			}
		}

		Server::Server(boost::asio::io_service &io):m_work(io)
		{
			auto rng = new Botan::AutoSeeded_RNG;
			auto mgr = new Botan::TLS::Session_Manager_In_Memory(*rng);
			auto creds = new Credentials(*rng);
			_ctx = std::make_unique<TLSContext>
				(rng, mgr, creds, new Policy);
		}

		Server::~Server()
		{
			spdlog::drop("Server");
		}

		void Server::setCA(std::string path)
		{
			_ctx->creds->addCA(path);
		}

		void Server::setCertAndKey(std::string certPath, std::string keyPath)
		{
			_ctx->creds->addPair(certPath, keyPath);
		}

		void Server::bind(std::string port, std::string bindAddress)
		{
			ip::tcp::endpoint bindEp;
			if (bindAddress.size() == 0) {
				bindEp = ip::tcp::endpoint(ip::tcp::v4(), std::stoi(port));
			}
			else {
				bindEp = ip::tcp::endpoint(ip::address::from_string(bindAddress), std::stoi(port));
			}
			m_logger->info("Linsten at {}:{}", bindEp.address().to_string(), bindEp.port());
			m_tcpAcceptor.reset(new ip::tcp::acceptor(m_work.get_io_service(), bindEp));
			m_tcpAcceptor->set_option(ip::tcp::no_delay(true));
		}

		void Server::start()
		{
			startAccept();
		}

		void Server::startAccept()
		{
			auto tunnel = std::make_shared<ServerProxyTunnel>(*_ctx, m_work.get_io_service());
			//tunnel->onDisconnected = std::bind(&Server::startAccept, this);
			m_logger->info("Start accept");
			m_tcpAcceptor->async_accept(tunnel->connection(), [this, tunnel](const boost::system::error_code &ec) {
				if (!ec) {
					tunnel->connection().set_option(boost::asio::ip::tcp::no_delay(true));
					auto ep = tunnel->connection().remote_endpoint();
					m_logger->info("New tunnel connection from {}:{}",ep.address().to_string(),ep.port());
					//tunnelSet.insert(tunnel);
					tunnel->start();
					startAccept();
				}
			});
		}
	}
}