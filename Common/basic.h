#pragma once
#ifndef MYPROXY_BASIC
#define MYPROXY_BASIC

#include "define.h"
#include "packages.h"
#include <boost/asio.hpp>
#include <tuple>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <utility>
#include <mutex>
#include <shared_mutex>
//log
#include <spdlog/spdlog.h>

namespace MyProxy {

	class BasicProxySession;

	class SessionManager {
	public:
		std::shared_ptr<BasicProxySession> get(SessionId id);
		bool insertAndStart(std::shared_ptr<BasicProxySession> session);
		bool remove(SessionId id);
		void clear();
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
		std::function<void()> onReady;
		std::function<void()> onDisconnected;
		BasicProxyTunnel(boost::asio::io_context &io, std::string loggerName = "Tunnel");
		virtual ~BasicProxyTunnel();
		virtual void start() = 0;
		SessionManager& manager() {
			return m_manager;
		}
		boost::asio::ip::tcp::socket& connection() {
			return _connection;
		}
		virtual void write(std::shared_ptr<DataVec> dataPtr) = 0;
		void sessionDestroyNotify(SessionId id);
	protected:
		boost::asio::io_context& service() {
			return io;
		}
		Logger& logger() {
			return m_logger;
		}
		void dispatch(std::shared_ptr<SessionPackage> package);
	private:
		boost::asio::io_context &io;
		boost::asio::ip::tcp::socket _connection;
		SessionManager m_manager;
		Logger m_logger;
	};

	class BasicProxySession {
	public:
		BasicProxySession(SessionId id, boost::asio::io_context &io, std::string loggerName = "Session") :
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
		//destroy session, if !notified, notify peer
		virtual void destroy(bool notified = false) = 0;
		virtual void setRunning(bool running) = 0;
		// *** unsafe
		virtual bool running() = 0;
		virtual void setTunnel(std::shared_ptr<BasicProxyTunnel> tunnel) { 
			if (!tunnel) {
				throw std::runtime_error("BasicProxySession::setTunnel(): parameter: tunnel(std::shared_ptr<BasicProxyTunnel>) unavailable");
			}
			this->_tunnel = tunnel; 
		}
		//virtual void newPackage(std::shared_ptr<SessionPackage> package) = 0;
		std::function<void(std::shared_ptr<SessionPackage>)> onReceived = [](std::shared_ptr<SessionPackage>) {};
	protected:
		boost::asio::io_context& service() {
			return io;
		}
		std::shared_ptr<BasicProxyTunnel>& tunnel() { return _tunnel; }
		Logger logger() {
			return m_logger;
		}
	private:
		boost::asio::io_context &io;
		const SessionId m_id;
		std::shared_ptr<BasicProxyTunnel> _tunnel;
		Logger m_logger;
	};


	template <typename T>
	void unused(const T&) {

	}
}


#endif // !MyProxyBasic
