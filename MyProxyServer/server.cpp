#include "server.h"
#include <botan/x509path.h>

using namespace boost::asio;

namespace MyProxy {
	namespace Server {

		std::shared_mutex ResolveCache::_resolveCacheMutex;

		//template<typename Protocol>
		//const typename ResolveCache::CacheRecord<Protocol>::ResultType ResolveCache::CacheRecord<Protocol>::end = typename Protocol::resolver::iterator();

		//template <typename Protocol>
		//const typename ResolveCache::CacheMapType<Protocol>::iterator ResolveCache::invalid = typename ResolveCache::CacheMapType<Protocol>::iterator();

		template<typename Protocol>
		typename ResolveCache::CacheMapType<Protocol> ResolveCache::_resolveCache = typename ResolveCache::CacheMapType<Protocol>(0,
			std::bind(&ResolveCache::queryHasher, std::placeholders::_1),
			std::bind(&ResolveCache::queryEqualTo, std::placeholders::_1, std::placeholders::_2)
			);

		bool ServerProxyTunnel::tls_session_established(const Botan::TLS::Session & session)
		{
			auto cert_chain = session.peer_certs();
			auto cas = _ctx.creds->trusted_certificate_authorities("tls-server", "");
			if (cert_chain.empty() && !cas.empty())
			{
				channel()->send_fatal_alert(Botan::TLS::Alert::NO_CERTIFICATE);
				throw std::invalid_argument("Certificate chain was empty");
			}
			Botan::Path_Validation_Result result = Botan::x509_path_validate(
				cert_chain,
				Botan::Path_Validation_Restrictions(),
				cas
			);
			if (!result.successful_validation()) {
				channel()->send_fatal_alert(Botan::TLS::Alert::BAD_CERTIFICATE);
				throw std::invalid_argument(result.result_string().c_str());
			}
			return true;
		}

		void ServerProxyTunnel::handleRead(std::shared_ptr<DataVec> data)
		{
			//if (!_running.load()) {
			//	logger()->warn("handleRead() cancel: tunnel stoped");
			//	return;
			//}
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

		Server::Server(boost::asio::io_context &io):_io(io),m_work(io.get_executor())
		{
			auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
			auto mgr = std::make_unique<Botan::TLS::Session_Manager_In_Memory>(*rng);
			auto creds = std::make_unique<MyProxy::Credentials>("tls-server", *rng);
			auto policy = std::make_unique<MyProxy::Policy>();
			_ctx = std::make_unique<TLSContext>
				(std::move(rng), std::move(mgr), std::move(creds), std::move(policy));
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
			m_tcpAcceptor.reset(new ip::tcp::acceptor(m_work.get_executor().context(), bindEp));
			m_tcpAcceptor->set_option(ip::tcp::no_delay(true));
		}

		void Server::start()
		{
			startAccept();
		}

		void Server::startAccept()
		{
			auto tunnel = std::make_shared<ServerProxyTunnel>(*_ctx, _io);
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