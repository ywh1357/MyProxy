#pragma once
#ifndef MYPROXY_BASIC
#define MYPROXY_BASIC

#include "define.h"
#include "packages.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
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
		using ssl_socket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
		BasicProxyTunnel(boost::asio::io_service &io, std::string loggerName = "Tunnel");
		virtual ~BasicProxyTunnel();
		virtual void start() = 0;
		std::shared_ptr<BasicProxyTunnel> self() {
			return shared_from_this();
		}
		inline bool ready() {
			return _handshakeFinished.load(); //wrong?
		}
		SessionManager& manager() {
			return m_manager;
		}
		boost::asio::ip::tcp::socket& connection() {
			return _connection;
		}
		virtual void write(std::shared_ptr<DataVec> dataPtr) = 0;
		void sessionDestroyNotify(SessionId id);
	protected:
		virtual void write_ex(std::shared_ptr<DataVec> dataPtr);
		virtual void write_impl();
		virtual void startProcess();
		virtual void nextRead();
		virtual void handleRead(std::shared_ptr<DataVec> data) = 0;
		void dispatch(std::shared_ptr<SessionPackage> package);
		boost::asio::streambuf& readbuf() {
			return m_readBuffer;
		}
		boost::asio::io_service& service() {
			return io;
		}
		Logger& logger() {
			return m_logger;
		}
		void disconnect();
	public:
		std::function<void()> onReady;
		std::function<void()> onDisconnected;
	protected:
		std::atomic<bool> _running{ true };
		std::atomic<bool> _handshakeFinished{ false };
		virtual void onReceived(const boost::system::error_code &ec, size_t bytes) = 0;
	private:
		boost::asio::io_service &io;
		boost::asio::ip::tcp::socket _connection;
		boost::asio::strand m_writeStrand;
		//boost::asio::strand m_readStrand; //not needed
		std::queue<std::shared_ptr<DataVec>> m_writeQueue;
		boost::asio::streambuf m_readBuffer;
		SessionManager m_manager;
		Logger m_logger;
	};

	class BasicProxySession {
	public:
		BasicProxySession(SessionId id, boost::asio::io_service &io, std::string loggerName = "Session") :
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
		boost::asio::io_service& service() {
			return io;
		}
		std::shared_ptr<BasicProxyTunnel>& tunnel() { return _tunnel; }
		Logger logger() {
			return m_logger;
		}
	private:
		boost::asio::io_service &io;
		const SessionId m_id;
		std::shared_ptr<BasicProxyTunnel> _tunnel;
		Logger m_logger;
	};


	template <typename T>
	void unused(const T&) {

	}
}


#endif // !MyProxyBasic
