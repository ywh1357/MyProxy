#include "basic.h"

using namespace boost::asio;

namespace MyProxy {
	IoHelper& operator<<(IoHelper&& io, const Package& package)
	{
		io << package.toDataVec();
		return io;
	}
	IoHelper& operator>>(IoHelper&& io, Package& package)
	{
		Package::SizeType size;
		io.getCastedValues<uint8_t, Package::SizeType>(package.type, size);
		return io;
	}

	IoHelper& operator<<(IoHelper&& io, const SessionPackage& package)
	{
		io.putCastedValues<uint8_t, Package::SizeType, SessionId, DataVec>(package.type,package.size(), package.sessionId, package.data);
		return io;
	}
	IoHelper& operator>>(IoHelper&& io, SessionPackage& package)
	{
		SessionPackage::SizeType size;
		io.getCastedValues<uint8_t, Package::SizeType, SessionId>(package.type, size, package.sessionId);
		package.data.resize(package.calcDataSize(size));
		io.getValues(package.data);
		//package.data = io.getValue<DataVec>(package.calcDataSize(size));
		return io;
	}

	IoHelper & operator<<(IoHelper && io, const NewSessionRequest & package)
	{
		io.putCastedValues<uint8_t, Package::SizeType, uint8_t, SessionId, uint8_t, uint8_t, DataVec, uint16_t>
			(package.type,package.size(),package.method,package.id,package.protoType,package.addrType,package.host,package.port);
		return io;
	}

	IoHelper & operator>>(IoHelper && io, NewSessionRequest & package)
	{
		SessionPackage::SizeType size;
		io.getCastedValues<uint8_t, Package::SizeType, uint8_t, SessionId, uint8_t, uint8_t>
			(package.type, size, package.method, package.id, package.protoType, package.addrType);
		package.host.resize(package.calcHostSize(size));
		io.getValues(package.host, package.port);
		return io;
	}

	IoHelper & operator>>(IoHelper & io, SessionDestoryNotify & package)
	{
		SessionPackage::SizeType size;
		io.getCastedValues<uint8_t, Package::SizeType, uint8_t, SessionId>
			(package.type, size, package.method, package.id);
		return io;
	}

	std::shared_ptr<spdlog::logger> SessionManager::logger = spdlog::stdout_color_mt("SessionManager");;

	std::shared_ptr<BasicProxySession> MyProxy::SessionManager::get(SessionId id)
	{
		std::shared_lock<std::shared_mutex> locker{ sessionsMutex };
		auto iter = m_sessions.find(id);
		if (iter != m_sessions.end()) {
			return (*iter).second;
		}
		else {
			return std::shared_ptr<BasicProxySession>();
		}
	}
	bool SessionManager::insertAndStart(std::shared_ptr<BasicProxySession> session)
	{
		std::unique_lock<std::shared_mutex> lokcer{ sessionsMutex };
		auto result = m_sessions.insert(std::pair<SessionId, std::shared_ptr<BasicProxySession>>(session->id(), session));
		lokcer.unlock();
		if(result.second)
			session->start();
		return result.second;
	}
	bool SessionManager::remove(SessionId id)
	{
		std::unique_lock<std::shared_mutex> lokcer{ sessionsMutex };
		auto iter = m_sessions.find(id);
		if (iter != m_sessions.end()) {
			auto session = (*iter).second;
			m_sessions.erase(iter);
			lokcer.unlock();
			session->stop();
			return true;
		}
		else {
			lokcer.unlock();
			logger->trace("remove(): session ID: {} not found.", id);
			return false;
		}
	}
	void SessionManager::setNotified(SessionId id)
	{
		std::unique_lock<std::shared_mutex> locker{ destroyeNotifiedSessionsMutex };
		if (destroyeNotiyedSessions.find(id) != destroyeNotiyedSessions.end()) {
			return;
		}
		destroyeNotiyedSessions.insert(id);
	}
	bool SessionManager::checkNotified(SessionId id)
	{
		std::shared_lock<std::shared_mutex> locker{ destroyeNotifiedSessionsMutex };
		if (destroyeNotiyedSessions.find(id) != destroyeNotiyedSessions.end()) {
			return true;
		}
		return false;
	}
	BasicProxyTunnel::BasicProxyTunnel(boost::asio::io_service & io, boost::asio::ssl::context &ctx, std::string loggerName) :
		io(io), m_writeStrand(io), m_tunnelConnection(io, ctx)
	{
		m_logger = spdlog::get(loggerName);
		if (!m_logger) {
			m_logger = spdlog::stdout_color_mt(loggerName);
		}
	}
	BasicProxyTunnel::~BasicProxyTunnel()
	{
	}
	void BasicProxyTunnel::write(std::shared_ptr<DataVec> dataPtr)
	{
		m_writeStrand.post([this, dataPtr = std::move(dataPtr), self = shared_from_this()]{
			if (!_running.load()) {
				m_logger->warn("BasicProxyTunnel::write() failed: Tunnel not running");
				return;
			}
			m_writeQueue.push(std::move(dataPtr));
			if (m_writeQueue.size() > 1) {
				return;
			}
			else {
				//m_writeStrand.post(std::bind(&BasicProxyTunnel::write_impl, this));
				write_impl();
			}
		});
	}
	void BasicProxyTunnel::sessionDestroyNotify(SessionId id)
	{
		SessionDestoryNotify notify{ id };
		write(std::make_shared<DataVec>(notify.toDataVec()));
		m_manager.setNotified(id);
	}
	void BasicProxyTunnel::disconnect()
	{
		if (!_running.exchange(false))
			return;
		if (onDisconnected) {
			onDisconnected();
		}
		std::function<void()> destroy = [this, self = shared_from_this()] {
			size_t destroyCount = 0;
			for (auto &session : m_manager.m_sessions) {
				session.second->stop();
				++destroyCount;
			}
			m_manager.m_sessions.clear();
			if (_running.load()) {
				disconnect();
			}
			boost::system::error_code ec;
			connection().close(ec);
			if (ec) {
				m_logger->debug("Close error: ", ec.message());
			}
			m_logger->debug("Disconnected");
		};
		if (!_handshakeFinished.exchange(false)) {
			destroy();
			return;
		}
		m_tunnelConnection.async_shutdown([this, destroy, self = shared_from_this()](const boost::system::error_code &ec){
			if (ec)
				m_logger->debug("SSL shutdown error: ", ec.message());
			destroy();
		});
	}
	void BasicProxyTunnel::write_impl()
	{
		if (m_writeQueue.empty()) {
			m_logger->warn("write queue empty");
			return;
		}
		async_write(m_tunnelConnection, boost::asio::buffer(*m_writeQueue.front()), boost::asio::transfer_all(),
			m_writeStrand.wrap([this, self = shared_from_this()](const boost::system::error_code &ec, size_t) {
			m_writeQueue.pop(); //drop
			if (ec) {
				m_logger->error("write error: ", ec.message());
				disconnect();
				return;
			}
			if (!m_writeQueue.empty()) {
				//m_writeStrand.post(std::bind(&BasicProxyTunnel::write_impl, this));
				write_impl();
			}
		}));
	}
	void BasicProxyTunnel::startProcess()
	{
		_handshakeFinished.store(true);
		nextRead();
	}

	void MyProxy::BasicProxyTunnel::nextRead()
	{
		using namespace boost::asio;
		async_read(m_tunnelConnection, m_readBuffer,
			[this, self = shared_from_this()](const boost::system::error_code &ec, size_t bytes) -> size_t {
			if (ec)
				return 0;
			return Package::remainBytes(buffer_cast<const char*>(m_readBuffer.data()), bytes);
		}, std::bind(&BasicProxyTunnel::handleRead, this, std::placeholders::_1, std::placeholders::_2, shared_from_this()));
	}

	void BasicProxyTunnel::dispatch(std::shared_ptr<SessionPackage> package)
	{
		auto session = m_manager.get(package->sessionId);
		if (session) {
			session->onReceived(package);
		}
		else {
			if (!m_manager.checkNotified(package->sessionId)){
				m_logger->debug("dispatch(): session ID: {} not found", package->sessionId);
				sessionDestroyNotify(package->sessionId);
			}
		}
	}
}

