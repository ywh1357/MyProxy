#include "basic.h"
#include "iohelper.h"

using namespace boost::asio;

namespace MyProxy {
	
	std::shared_ptr<spdlog::logger> SessionManager::logger = spdlog::stdout_color_mt("SessionManager");;
	/*
		SessionManager implement
	*/
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
	void SessionManager::clear()
	{
		std::unique_lock<std::shared_mutex> lokcer{ sessionsMutex };
		for (auto &iter : m_sessions) {
			iter.second->setRunning(false);
			iter.second->stop();
		}
		m_sessions.clear();
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

	/*
		BasicProxyTunnel implement
	*/
	BasicProxyTunnel::BasicProxyTunnel(boost::asio::io_service & io, std::string loggerName) :
		io(io), m_writeStrand(io), _connection(io)
	{
		m_logger = spdlog::get(loggerName);
		if (!m_logger) {
			m_logger = spdlog::stdout_color_mt(loggerName);
		}
	}
	BasicProxyTunnel::~BasicProxyTunnel()
	{
	}
	void BasicProxyTunnel::sessionDestroyNotify(SessionId id)
	{
		SessionDestoryNotify notify{ id };
		write_ex(std::make_shared<DataVec>(notify.toDataVec()));
		m_manager.setNotified(id);
	}
	void BasicProxyTunnel::disconnect()
	{
		if (!_running.exchange(false))
			return;
		if (onDisconnected) {
			onDisconnected();
		}
		m_manager.clear();
		boost::system::error_code ec;
		_connection.shutdown(_connection.shutdown_both, ec);
		if (ec) {
			m_logger->debug("shutdown error: ", ec.message());
		}
		ec.clear();
		_connection.close(ec);
		if (ec) {
			m_logger->debug("Close error: ", ec.message());
		}
		m_logger->debug("Disconnected");
	}
	void BasicProxyTunnel::write_ex(std::shared_ptr<DataVec> dataPtr)
	{
		if (!_running.load())
			return;
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
	void BasicProxyTunnel::write_impl()
	{
		if (m_writeQueue.empty()) {
			m_logger->warn("write queue empty");
			return;
		}
		async_write(_connection, boost::asio::buffer(*m_writeQueue.front()), boost::asio::transfer_all(),
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

	void BasicProxyTunnel::nextRead()
	{
		using namespace boost::asio;
		_connection.async_read_some(
			m_readBuffer.prepare(8 * 1024),
			std::bind(&BasicProxyTunnel::onReceived, this, std::placeholders::_1, std::placeholders::_2, shared_from_this())
		);
	}

	void BasicProxyTunnel::dispatch(std::shared_ptr<SessionPackage> package)
	{
		auto session = m_manager.get(package->sessionId);
		if (session && session->onReceived) {
			session->onReceived(package);
		}
		else {
			if (!m_manager.checkNotified(package->sessionId)){
				m_logger->debug("dispatch() cancel: session ID: {} not found or not ready", package->sessionId);
				sessionDestroyNotify(package->sessionId);
			}
		}
	}
}

