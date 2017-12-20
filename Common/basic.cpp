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
		io(io), _connection(io)
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
		write(std::make_shared<DataVec>(notify.toDataVec()));
		m_manager.setNotified(id);
	}
	void BasicProxyTunnel::dispatch(std::shared_ptr<SessionPackage> package)
	{
		auto session = m_manager.get(package->sessionId);
		if (session && session->onReceived) {
			session->onReceived(package);
		}
		else {
			if (!m_manager.checkNotified(package->sessionId)) {
				logger()->debug("dispatch() cancel: session ID: {} not found or not ready", package->sessionId);
				sessionDestroyNotify(package->sessionId);
			}
		}
	}

}

